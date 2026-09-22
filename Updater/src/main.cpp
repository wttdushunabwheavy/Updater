#include "main.h"

#include <httplib.h>

#include <Windows.h>
#include <bcrypt.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm> 
#include <thread>
#include <vector>
#include <chrono>
#include <system_error>

#pragma comment(lib, "bcrypt.lib")


namespace fs = std::filesystem;


// ============================================================
// Constants
// ============================================================

namespace
{
    constexpr const char* DefaultServerUrl =
        "http://89.28.48.2:8080/";

    std::string ServerUrl =
        DefaultServerUrl;

    constexpr size_t HashBufferSize =
        1024 * 1024;


    // ========================================================
    // String helpers
    // ========================================================

    std::string Trim(
        const std::string& String)
    {
        size_t Begin = 0;
        size_t End = String.size();

        while (Begin < End &&
               std::isspace(
                   static_cast<unsigned char>(
                       String[Begin])))
        {
            ++Begin;
        }

        while (End > Begin &&
               std::isspace(
                   static_cast<unsigned char>(
                       String[End - 1])))
        {
            --End;
        }

        return String.substr(
            Begin,
            End - Begin
        );
    }


    std::string ToLower(
        std::string String)
    {
        std::transform(
            String.begin(),
            String.end(),
            String.begin(),
            [](unsigned char Character)
            {
                return static_cast<char>(
                    std::tolower(Character)
                );
            });

        return String;
    }


    std::string NormalizePath(
        const fs::path& Path)
    {
        std::string Result =
            Path.generic_string();

        while (!Result.empty() &&
               Result.front() == '/')
        {
            Result.erase(
                Result.begin()
            );
        }

        return Result;
    }


    std::string NormalizeManifestPath(
        std::string Path)
    {
        Path = Trim(Path);

        std::replace(
            Path.begin(),
            Path.end(),
            '\\',
            '/'
        );

        while (!Path.empty() &&
               Path.front() == '/')
        {
            Path.erase(
                Path.begin()
            );
        }

        return Path;
    }


    bool IsCfgFile(
        const fs::path& Path)
    {
        return ToLower(
            Path.extension().string()
        ) == ".cfg";
    }


    // ========================================================
    // URL encoding
    // ========================================================

    bool IsUrlSafeCharacter(
        unsigned char Character)
    {
        return
            (Character >= 'a' &&
             Character <= 'z') ||

            (Character >= 'A' &&
             Character <= 'Z') ||

            (Character >= '0' &&
             Character <= '9') ||

            Character == '-' ||
            Character == '_' ||
            Character == '.' ||
            Character == '~';
    }


    std::string UrlEncodePath(
        const std::string& Path)
    {
        std::ostringstream Result;

        Result << std::uppercase
               << std::hex;

        for (unsigned char Character :
             Path)
        {
            if (IsUrlSafeCharacter(Character))
            {
                Result << static_cast<char>(
                    Character
                );
            }
            else if (Character == '/')
            {
                Result << '/';
            }
            else
            {
                Result << '%'
                       << std::setw(2)
                       << std::setfill('0')
                       << static_cast<int>(
                           Character
                       );
            }
        }

        return Result.str();
    }


    // ========================================================
    // SHA-256
    // ========================================================

    std::string CalculateSHA256(
        const fs::path& Path)
    {
        std::ifstream File(
            Path,
            std::ios::binary
        );

        if (!File)
            return {};


        BCRYPT_ALG_HANDLE Algorithm =
            nullptr;

        BCRYPT_HASH_HANDLE Hash =
            nullptr;


        if (BCryptOpenAlgorithmProvider(
                &Algorithm,
                BCRYPT_SHA256_ALGORITHM,
                nullptr,
                0) != 0)
        {
            return {};
        }


        DWORD ObjectSize = 0;
        DWORD DataSize = 0;


        if (BCryptGetProperty(
                Algorithm,
                BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(
                    &ObjectSize),
                sizeof(ObjectSize),
                &DataSize,
                0) != 0)
        {
            BCryptCloseAlgorithmProvider(
                Algorithm,
                0
            );

            return {};
        }


        std::vector<unsigned char>
            HashObject(
                ObjectSize
            );


        if (BCryptCreateHash(
                Algorithm,
                &Hash,
                HashObject.data(),
                ObjectSize,
                nullptr,
                0,
                0) != 0)
        {
            BCryptCloseAlgorithmProvider(
                Algorithm,
                0
            );

            return {};
        }


        std::vector<unsigned char>
            Buffer(
                HashBufferSize
            );


        while (File)
        {
            File.read(
                reinterpret_cast<char*>(
                    Buffer.data()),
                static_cast<std::streamsize>(
                    Buffer.size())
            );


            const std::streamsize
                BytesRead =
                    File.gcount();


            if (BytesRead <= 0)
                break;


            if (BCryptHashData(
                    Hash,
                    Buffer.data(),
                    static_cast<ULONG>(
                        BytesRead),
                    0) != 0)
            {
                BCryptDestroyHash(Hash);

                BCryptCloseAlgorithmProvider(
                    Algorithm,
                    0
                );

                return {};
            }
        }


        DWORD HashLength = 0;


        if (BCryptGetProperty(
                Algorithm,
                BCRYPT_HASH_LENGTH,
                reinterpret_cast<PUCHAR>(
                    &HashLength),
                sizeof(HashLength),
                &DataSize,
                0) != 0)
        {
            BCryptDestroyHash(Hash);

            BCryptCloseAlgorithmProvider(
                Algorithm,
                0
            );

            return {};
        }


        std::vector<unsigned char>
            HashBytes(
                HashLength
            );


        if (BCryptFinishHash(
                Hash,
                HashBytes.data(),
                HashLength,
                0) != 0)
        {
            BCryptDestroyHash(Hash);

            BCryptCloseAlgorithmProvider(
                Algorithm,
                0
            );

            return {};
        }


        BCryptDestroyHash(Hash);

        BCryptCloseAlgorithmProvider(
            Algorithm,
            0
        );


        std::ostringstream Result;

        Result << std::uppercase
               << std::hex
               << std::setfill('0');


        for (unsigned char Byte :
             HashBytes)
        {
            Result << std::setw(2)
                   << static_cast<int>(
                       Byte
                   );
        }


        return Result.str();
    }


    // ========================================================
    // Excluded paths
    // ========================================================

    bool IsExcludedPath(
        const fs::path& Path)
    {
        std::ifstream File(
            "ExcludedPaths.cfg"
        );

        if (!File)
            return false;


        const std::string Current =
            NormalizePath(Path);


        std::string Line;


        while (std::getline(
            File,
            Line))
        {
            Line = Trim(Line);

            if (Line.empty())
                continue;

            if (Line[0] == '#')
                continue;


            Line =
                NormalizeManifestPath(Line);


            if (Current == Line)
                return true;


            if (Current.rfind(
                    Line + "/",
                    0) == 0)
            {
                return true;
            }
        }


        return false;
    }


    // ========================================================
    // HTTP URL helpers
    // ========================================================

    bool SplitHttpUrl(
        const std::string& Url,
        std::string& BaseUrl,
        std::string& RequestPath)
    {
        const size_t SchemeEnd = Url.find("://");

        if (SchemeEnd == std::string::npos)
            return false;

        const std::string Scheme =
            ToLower(Url.substr(0, SchemeEnd));

        // Current updater uses plain HTTP.
        // HTTPS can be added later with httplib::SSLClient.
        if (Scheme != "http")
            return false;

        const size_t AuthorityStart = SchemeEnd + 3;
        const size_t PathStart = Url.find('/', AuthorityStart);

        if (PathStart == std::string::npos)
        {
            BaseUrl = Url;
            RequestPath = "/";
            return true;
        }

        BaseUrl = Url.substr(0, PathStart);
        RequestPath = Url.substr(PathStart);

        if (RequestPath.empty())
            RequestPath = "/";

        return true;
    }


    bool IsSafeRelativePath(
        const std::string& Path)
    {
        if (Path.empty())
            return false;

        const fs::path Relative(Path);

        if (Relative.is_absolute())
            return false;

        if (Relative.has_root_name() ||
            Relative.has_root_directory())
        {
            return false;
        }

        for (const auto& Part : Relative)
        {
            if (Part == "..")
                return false;
        }

        return true;
    }


    // ========================================================
    // HTTP error helper
    // ========================================================

    void PrintHttpError(
        const httplib::Result& Result)
    {
        if (Result)
        {
            std::cout
                << "HTTP status: "
                << Result->status
                << '\n';

            return;
        }


        std::cout
            << "HTTP request failed: "
            << httplib::to_string(
                   Result.error())
            << '\n';
    }
}


// ============================================================
// GeneratorProcess
// ============================================================

bool GeneratorProcess::CreatePipes()
{
    SECURITY_ATTRIBUTES SecurityAttributes{};

    SecurityAttributes.nLength =
        sizeof(SecurityAttributes);

    SecurityAttributes.bInheritHandle =
        TRUE;

    SecurityAttributes.lpSecurityDescriptor =
        nullptr;


    HANDLE InRead = nullptr;
    HANDLE InWrite = nullptr;

    HANDLE OutRead = nullptr;
    HANDLE OutWrite = nullptr;


    if (!CreatePipe(
            &InRead,
            &InWrite,
            &SecurityAttributes,
            0))
    {
        return false;
    }


    if (!SetHandleInformation(
            InWrite,
            HANDLE_FLAG_INHERIT,
            0))
    {
        CloseHandle(InRead);
        CloseHandle(InWrite);

        return false;
    }


    if (!CreatePipe(
            &OutRead,
            &OutWrite,
            &SecurityAttributes,
            0))
    {
        CloseHandle(InRead);
        CloseHandle(InWrite);

        return false;
    }


    if (!SetHandleInformation(
            OutRead,
            HANDLE_FLAG_INHERIT,
            0))
    {
        CloseHandle(InRead);
        CloseHandle(InWrite);

        CloseHandle(OutRead);
        CloseHandle(OutWrite);

        return false;
    }


    StdInRead =
        InRead;

    StdInWrite =
        InWrite;

    StdOutRead =
        OutRead;

    StdOutWrite =
        OutWrite;


    return true;
}


void GeneratorProcess::ClosePipes()
{
    if (StdInRead)
    {
        CloseHandle(
            static_cast<HANDLE>(
                StdInRead));

        StdInRead = nullptr;
    }


    if (StdInWrite)
    {
        CloseHandle(
            static_cast<HANDLE>(
                StdInWrite));

        StdInWrite = nullptr;
    }


    if (StdOutRead)
    {
        CloseHandle(
            static_cast<HANDLE>(
                StdOutRead));

        StdOutRead = nullptr;
    }


    if (StdOutWrite)
    {
        CloseHandle(
            static_cast<HANDLE>(
                StdOutWrite));

        StdOutWrite = nullptr;
    }


    if (ProcessHandle)
    {
        CloseHandle(
            static_cast<HANDLE>(
                ProcessHandle));

        ProcessHandle = nullptr;
    }


    if (ThreadHandle)
    {
        CloseHandle(
            static_cast<HANDLE>(
                ThreadHandle));

        ThreadHandle = nullptr;
    }
}


bool GeneratorProcess::RunCommand(
    const fs::path& Executable,
    const std::string& Command)
{
    if (!CreatePipes())
        return false;


    HANDLE ChildStdIn =
        static_cast<HANDLE>(
            StdInRead);

    HANDLE ParentStdIn =
        static_cast<HANDLE>(
            StdInWrite);

    HANDLE ChildStdOut =
        static_cast<HANDLE>(
            StdOutWrite);

    HANDLE ParentStdOut =
        static_cast<HANDLE>(
            StdOutRead);


    STARTUPINFOW StartupInfo{};

    PROCESS_INFORMATION ProcessInfo{};


    StartupInfo.cb =
        sizeof(StartupInfo);


    StartupInfo.dwFlags |=
        STARTF_USESTDHANDLES;


    StartupInfo.hStdInput =
        ChildStdIn;

    StartupInfo.hStdOutput =
        ChildStdOut;

    StartupInfo.hStdError =
        ChildStdOut;


    std::wstring CommandLine =
        L"\"" +
        Executable.wstring() +
        L"\"";


    if (!CreateProcessW(
            nullptr,
            CommandLine.data(),
            nullptr,
            nullptr,
            TRUE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &StartupInfo,
            &ProcessInfo))
    {
        ClosePipes();

        return false;
    }


    ProcessHandle =
        ProcessInfo.hProcess;

    ThreadHandle =
        ProcessInfo.hThread;


    CloseHandle(
        ChildStdIn);

    ChildStdIn = nullptr;

    StdInRead = nullptr;


    CloseHandle(
        ChildStdOut);

    ChildStdOut = nullptr;

    StdOutWrite = nullptr;


    std::string Output;


    std::thread Reader(
        [&]()
        {
            char Buffer[4096];

            DWORD BytesRead = 0;


            while (ReadFile(
                       ParentStdOut,
                       Buffer,
                       sizeof(Buffer) - 1,
                       &BytesRead,
                       nullptr))
            {
                if (BytesRead == 0)
                    break;


                Buffer[BytesRead] =
                    '\0';


                Output += Buffer;
            }
        });


    // ManifestGenerator is interactive, but it also treats EOF as
    // the end of its input stream. Send exactly one command and then
    // close stdin. The generator will finish that command and exit
    // when it reaches EOF.
    std::string Input =
        Command +
        "\n";


    DWORD BytesWritten = 0;


    bool WriteSuccess =
        WriteFile(
            ParentStdIn,
            Input.data(),
            static_cast<DWORD>(
                Input.size()),
            &BytesWritten,
            nullptr);


    CloseHandle(
        ParentStdIn);

    ParentStdIn = nullptr;

    StdInWrite = nullptr;


    if (!WriteSuccess)
    {
        WaitForSingleObject(
            static_cast<HANDLE>(
                ProcessHandle),
            INFINITE);


        if (Reader.joinable())
            Reader.join();


        CloseHandle(
            ParentStdOut);

        StdOutRead = nullptr;


        ClosePipes();

        return false;
    }


    WaitForSingleObject(
        static_cast<HANDLE>(
            ProcessHandle),
        INFINITE);


    DWORD ExitCode = 1;


    GetExitCodeProcess(
        static_cast<HANDLE>(
            ProcessHandle),
        &ExitCode);


    CloseHandle(
        ParentStdOut);

    ParentStdOut = nullptr;

    StdOutRead = nullptr;


    if (Reader.joinable())
        Reader.join();


    if (!Output.empty())
    {
        std::cout
            << Output;
    }


    const bool Success =
        ExitCode == 0;


    ClosePipes();

    return Success;
}


// ============================================================
// ManifestManager
// ============================================================

bool ManifestManager::DownloadManifest(
    const std::string& Url,
    const fs::path& OutputPath)
{
    std::cout
        << "[DOWNLOAD MANIFEST]\n"
        << "  URL: "
        << Url
        << '\n'
        << "  Output: "
        << OutputPath
        << '\n';


    /*
        Для manifest достаточно обычного
        буферизованного GET, потому что он маленький.

        Файлы несколько GB ниже скачиваются
        потоково через ContentReceiver.
    */


    std::string BaseUrl;
    std::string RequestPath;

    if (!SplitHttpUrl(
            Url,
            BaseUrl,
            RequestPath))
    {
        std::cout
            << "Invalid HTTP URL: "
            << Url
            << '\n';

        return false;
    }


    httplib::Client Client(
        BaseUrl
    );


    Client.set_connection_timeout(
        10,
        0
    );

    Client.set_read_timeout(
        30,
        0
    );

    Client.set_write_timeout(
        30,
        0
    );


    auto Result =
        Client.Get(
            RequestPath.c_str()
        );


    if (!Result)
    {
        PrintHttpError(Result);
        return false;
    }


    if (Result->status != 200)
    {
        std::cout
            << "Manifest download failed. "
            << "HTTP "
            << Result->status
            << '\n';

        return false;
    }


    std::ofstream File(
        OutputPath,
        std::ios::binary
    );


    if (!File)
    {
        std::cout
            << "Cannot create manifest file: "
            << OutputPath
            << '\n';

        return false;
    }


    File.write(
        Result->body.data(),
        static_cast<std::streamsize>(
            Result->body.size())
    );


    if (!File)
    {
        std::cout
            << "Failed to write manifest.\n";

        return false;
    }


    std::cout
        << "Manifest downloaded successfully.\n";


    return true;
}


bool ManifestManager::GenerateCfgManifest()
{
    GeneratorProcess Generator;

    return Generator.RunCommand(
        "ManifestGenerator.exe",
        "generatecfgmanifest"
    );
}


bool ManifestManager::GenerateNonCfgManifest()
{
    GeneratorProcess Generator;

    return Generator.RunCommand(
        "ManifestGenerator.exe",
        "generatenoncfgmanifest"
    );
}


bool ManifestManager::GenerateBothManifests()
{
    GeneratorProcess Generator;

    return Generator.RunCommand(
        "ManifestGenerator.exe",
        "generateboth"
    );
}


// ============================================================
// Manifest loading
// ============================================================

bool ManifestManager::LoadManifest(
    const fs::path& Path,
    Manifest& OutManifest) const
{
    OutManifest.clear();


    std::ifstream File(
        Path
    );

    if (!File)
    {
        std::cout
            << "Cannot open manifest: "
            << Path
            << '\n';

        return false;
    }


    std::string Line;

    size_t LineNumber = 0;


    while (std::getline(
        File,
        Line))
    {
        ++LineNumber;


        Line =
            Trim(Line);


        if (Line.empty())
            continue;


        if (Line[0] == '#')
            continue;


        const size_t FirstSeparator =
            Line.find('|');


        if (FirstSeparator ==
            std::string::npos)
        {
            std::cout
                << "Invalid manifest line "
                << LineNumber
                << ": "
                << Line
                << '\n';

            continue;
        }


        const size_t SecondSeparator =
            Line.find(
                '|',
                FirstSeparator + 1
            );


        if (SecondSeparator ==
            std::string::npos)
        {
            std::cout
                << "Invalid manifest line "
                << LineNumber
                << ": "
                << Line
                << '\n';

            continue;
        }


        const std::string PathString =
            NormalizeManifestPath(
                Line.substr(
                    0,
                    FirstSeparator
                )
            );


        const std::string SizeString =
            Trim(
                Line.substr(
                    FirstSeparator + 1,
                    SecondSeparator -
                    FirstSeparator -
                    1
                )
            );


        const std::string Hash =
            ToLower(
                Trim(
                    Line.substr(
                        SecondSeparator + 1
                    )
                )
            );


        if (PathString.empty() ||
            SizeString.empty() ||
            Hash.empty())
        {
            std::cout
                << "Invalid manifest line "
                << LineNumber
                << '\n';

            continue;
        }


        try
        {
            /*
                Проверяем, что Size действительно
                является числом.

                Пока ManifestEntry не хранит Size,
                поэтому само значение здесь
                не сохраняем.
            */

            std::stoull(
                SizeString
            );
        }
        catch (...)
        {
            std::cout
                << "Invalid file size at line "
                << LineNumber
                << '\n';

            continue;
        }


        ManifestEntry Entry;

        Entry.Path =
            PathString;

        Entry.Hash =
            Hash;


        OutManifest[PathString] =
            Entry;
    }


    return true;
}


// ============================================================
// Manifest comparison
// ============================================================

ManifestCompareResult
ManifestManager::Compare(
    const Manifest& Local,
    const Manifest& Remote) const
{
    ManifestCompareResult Result;


    // --------------------------------------------------------
    // Server -> local
    // --------------------------------------------------------

    for (const auto& [Path, RemoteEntry] :
         Remote)
    {
        auto LocalIt =
            Local.find(Path);


        if (LocalIt ==
            Local.end())
        {
            Result.Added.push_back(
                Path
            );

            continue;
        }


        if (ToLower(
                LocalIt->second.Hash) !=
            ToLower(
                RemoteEntry.Hash))
        {
            Result.Modified.push_back(
                Path
            );
        }
    }


    // --------------------------------------------------------
    // Local -> server
    // --------------------------------------------------------

    for (const auto& [Path, LocalEntry] :
         Local)
    {
        if (Remote.find(Path) ==
            Remote.end())
        {
            Result.Missing.push_back(
                Path
            );
        }
    }


    return Result;
}


size_t ManifestManager::CountFiles(
    const Manifest& ManifestData) const
{
    return ManifestData.size();
}


// ============================================================
// FileScanner
// ============================================================

bool FileScanner::IsCfgFile(
    const fs::path& Path) const
{
    const std::string Extension =
        ToLower(
            Path.extension().string()
        );


    const std::vector<std::string>
        Extensions =
            LoadCfgExtensions();


    if (!Extensions.empty())
    {
        return std::find(
                   Extensions.begin(),
                   Extensions.end(),
                   Extension
               )
               != Extensions.end();
    }


    return Extension == ".cfg";
}


bool FileScanner::IsExcluded(
    const fs::path& Path) const
{
    return IsExcludedPath(Path);
}


std::vector<std::string>
FileScanner::LoadCfgExtensions() const
{
    std::vector<std::string>
        Result;


    std::ifstream File(
        "CfgExtensions.cfg"
    );


    if (!File)
        return Result;


    std::string Line;


    while (std::getline(
        File,
        Line))
    {
        Line =
            Trim(Line);


        if (Line.empty())
            continue;


        if (Line[0] == '#')
            continue;


        Line =
            ToLower(Line);


        if (Line.front() != '.')
            Line =
                "." + Line;


        Result.push_back(
            Line
        );
    }


    return Result;
}


std::vector<std::string>
FileScanner::LoadExcludedPaths() const
{
    std::vector<std::string>
        Result;


    std::ifstream File(
        "ExcludedPaths.cfg"
    );


    if (!File)
        return Result;


    std::string Line;


    while (std::getline(
        File,
        Line))
    {
        Line =
            Trim(Line);


        if (Line.empty())
            continue;


        if (Line[0] == '#')
            continue;


        Result.push_back(
            NormalizeManifestPath(
                Line
            )
        );
    }


    return Result;
}


// ============================================================
// Scan all
// ============================================================

std::vector<FileInfo>
FileScanner::ScanAll() const
{
    std::vector<FileInfo>
        Result;


    try
    {
        for (const auto& Entry :
             fs::recursive_directory_iterator(
                 ".",
                 fs::directory_options::
                     skip_permission_denied))
        {
            if (!Entry.is_regular_file())
                continue;


            const fs::path Path =
                Entry.path();


            if (IsExcluded(Path))
                continue;


            FileInfo Info;

            Info.Path =
                Path;


            try
            {
                Info.Size =
                    fs::file_size(Path);
            }
            catch (...)
            {
                continue;
            }


            Info.Hash =
                CalculateSHA256(Path);


            Result.push_back(
                std::move(Info)
            );
        }
    }
    catch (...)
    {
    }


    return Result;
}


// ============================================================
// Scan CFG
// ============================================================

std::vector<FileInfo>
FileScanner::ScanCfg() const
{
    std::vector<FileInfo>
        Result;


    try
    {
        for (const auto& Entry :
             fs::recursive_directory_iterator(
                 ".",
                 fs::directory_options::
                     skip_permission_denied))
        {
            if (!Entry.is_regular_file())
                continue;


            const fs::path Path =
                Entry.path();


            if (IsExcluded(Path))
                continue;


            if (!IsCfgFile(Path))
                continue;


            FileInfo Info;

            Info.Path =
                Path;


            try
            {
                Info.Size =
                    fs::file_size(Path);
            }
            catch (...)
            {
                continue;
            }


            Info.Hash =
                CalculateSHA256(Path);


            Result.push_back(
                std::move(Info)
            );
        }
    }
    catch (...)
    {
    }


    return Result;
}


// ============================================================
// Scan non-CFG
// ============================================================

std::vector<FileInfo>
FileScanner::ScanNonCfg() const
{
    std::vector<FileInfo>
        Result;


    try
    {
        for (const auto& Entry :
             fs::recursive_directory_iterator(
                 ".",
                 fs::directory_options::
                     skip_permission_denied))
        {
            if (!Entry.is_regular_file())
                continue;


            const fs::path Path =
                Entry.path();


            if (IsExcluded(Path))
                continue;


            if (IsCfgFile(Path))
                continue;


            FileInfo Info;

            Info.Path =
                Path;


            try
            {
                Info.Size =
                    fs::file_size(Path);
            }
            catch (...)
            {
                continue;
            }


            Info.Hash =
                CalculateSHA256(Path);


            Result.push_back(
                std::move(Info)
            );
        }
    }
    catch (...)
    {
    }


    return Result;
}


// ============================================================
// Count all
// ============================================================

size_t FileScanner::CountAll() const
{
    size_t Count = 0;


    try
    {
        for (const auto& Entry :
             fs::recursive_directory_iterator(
                 ".",
                 fs::directory_options::
                     skip_permission_denied))
        {
            if (!Entry.is_regular_file())
                continue;


            if (IsExcluded(
                    Entry.path()))
            {
                continue;
            }


            ++Count;
        }
    }
    catch (...)
    {
    }


    return Count;
}


// ============================================================
// Count CFG
// ============================================================

size_t FileScanner::CountCfg() const
{
    size_t Count = 0;


    try
    {
        for (const auto& Entry :
             fs::recursive_directory_iterator(
                 ".",
                 fs::directory_options::
                     skip_permission_denied))
        {
            if (!Entry.is_regular_file())
                continue;


            if (IsExcluded(
                    Entry.path()))
            {
                continue;
            }


            if (IsCfgFile(
                    Entry.path()))
            {
                ++Count;
            }
        }
    }
    catch (...)
    {
    }


    return Count;
}


// ============================================================
// Count non-CFG
// ============================================================

size_t FileScanner::CountNonCfg() const
{
    size_t Count = 0;


    try
    {
        for (const auto& Entry :
             fs::recursive_directory_iterator(
                 ".",
                 fs::directory_options::
                     skip_permission_denied))
        {
            if (!Entry.is_regular_file())
                continue;


            if (IsExcluded(
                    Entry.path()))
            {
                continue;
            }


            if (!IsCfgFile(
                    Entry.path()))
            {
                ++Count;
            }
        }
    }
    catch (...)
    {
    }


    return Count;
}


// ============================================================
// FileDownloader
// ============================================================

bool FileDownloader::DownloadFile(
    const std::string& Url,
    const fs::path& Destination)
{
    std::cout
        << "[DOWNLOAD]\n"
        << "  URL: "
        << Url
        << '\n'
        << "  -> "
        << Destination
        << '\n';


    /*
        Destination = настоящий путь.

        Во время загрузки используем:

            file.ext.download

        чтобы оборванная загрузка не уничтожила
        уже существующий рабочий файл.
    */

    const fs::path TempPath =
        Destination.string() +
        ".download";


    std::error_code ec;


    if (!Destination.parent_path().empty())
    {
        fs::create_directories(
            Destination.parent_path(),
            ec
        );

        if (ec)
        {
            std::cout
                << "Failed to create directory: "
                << Destination.parent_path()
                << '\n';

            return false;
        }
    }


    fs::remove(
        TempPath,
        ec
    );


    /*
        cpp-httplib позволяет передавать
        ContentReceiver.

        Поэтому данные приходят кусками
        и сразу пишутся на диск.
    */

    std::string BaseUrl;
    std::string RequestPath;

    if (!SplitHttpUrl(
            Url,
            BaseUrl,
            RequestPath))
    {
        std::cout
            << "Invalid HTTP URL: "
            << Url
            << '\n';

        return false;
    }


    httplib::Client Client(
        BaseUrl
    );


    Client.set_connection_timeout(
        10,
        0
    );

    Client.set_read_timeout(
        60,
        0
    );

    Client.set_write_timeout(
        60,
        0
    );


    std::ofstream File(
        TempPath,
        std::ios::binary
    );


    if (!File)
    {
        std::cout
            << "Cannot create temporary file: "
            << TempPath
            << '\n';

        return false;
    }


    uintmax_t Downloaded = 0;


    auto Result =
        Client.Get(
            RequestPath.c_str(),
            [&](const char* Data,
                size_t DataSize)
            {
                File.write(
                    Data,
                    static_cast<std::streamsize>(
                        DataSize)
                );


                if (!File)
                    return false;


                Downloaded +=
                    DataSize;


                /*
                    Пока просто выводим объём.

                    Для больших файлов это позволит
                    видеть, что загрузка реально идёт.
                */

                if (Downloaded %
                    (100 * 1024 * 1024) <
                    DataSize)
                {
                    std::cout
                        << "  Downloaded: "
                        << Downloaded /
                               (1024 * 1024)
                        << " MB\n";
                }


                return true;
            }
        );


    File.close();


    if (!Result)
    {
        PrintHttpError(Result);

        fs::remove(
            TempPath,
            ec
        );

        return false;
    }


    if (Result->status != 200)
    {
        std::cout
            << "Download failed. HTTP "
            << Result->status
            << '\n';

        fs::remove(
            TempPath,
            ec
        );

        return false;
    }


    if (!fs::exists(
            TempPath,
            ec))
    {
        std::cout
            << "Temporary file was not created.\n";

        return false;
    }


    std::cout
        << "Download finished: "
        << Downloaded
        << " bytes\n";


    return true;
}


bool FileDownloader::DownloadFiles(
    const std::vector<std::string>& Paths)
{
    for (const std::string& RelativePath :
         Paths)
    {
        const std::string Normalized =

            NormalizeManifestPath(

                RelativePath

            );


        // Manifest paths include the local files/ prefix.

        // The server /file endpoint is already rooted at files/.

        std::string ServerPath =

            Normalized;


        if (ServerPath.rfind("files/", 0) == 0)

        {

            ServerPath.erase(0, 6);

        }


        if (!IsSafeRelativePath(ServerPath))
        {
            std::cout
                << "Unsafe download path: "
                << RelativePath
                << '\n';

            return false;
        }


        const std::string Encoded =
            UrlEncodePath(
                ServerPath
            );


        const std::string Url =
            ServerUrl +
            "file/" +
            Encoded;


        const fs::path Destination =
            fs::path(Normalized);

        const fs::path TempPath =
            Destination.string() +
            ".download";


        if (!DownloadFile(
                Url,
                Destination))
        {
            std::cout
                << "Failed to download: "
                << RelativePath
                << '\n';

            return false;
        }


        std::error_code ec;

        fs::remove(
            Destination,
            ec
        );

        ec.clear();

        fs::rename(
            TempPath,
            Destination,
            ec
        );

        if (ec)
        {
            std::cout
                << "Failed to finalize download: "
                << RelativePath
                << '\n'
                << "Error: "
                << ec.message()
                << '\n';

            return false;
        }
    }


    return true;
}


// ============================================================
// FileUpdater
// ============================================================

bool FileUpdater::ShouldUpdate(
    const std::string& RelativePath,
    bool CfgOnly) const
{
    const bool Cfg =
        IsCfgFile(
            fs::path(RelativePath)
        );


    if (CfgOnly)
        return Cfg;


    return !Cfg;
}


bool FileUpdater::IsExcluded(
    const fs::path& Path) const
{
    return IsExcludedPath(Path);
}


bool FileUpdater::UpdateFile(
    const std::string& RelativePath)
{
    std::cout
        << "[UPDATE] "
        << RelativePath
        << '\n';


    const std::string Normalized =



        NormalizeManifestPath(



            RelativePath



        );




    // Manifest paths include the local files/ prefix.



    // The server /file endpoint is already rooted at files/.



    std::string ServerPath =



        Normalized;




    if (ServerPath.rfind("files/", 0) == 0)



    {



        ServerPath.erase(0, 6);



    }




    if (!IsSafeRelativePath(ServerPath))
    {
        std::cout
            << "Unsafe update path: "
            << RelativePath
            << '\n';

        return false;
    }


    const std::string Encoded =
        UrlEncodePath(
            ServerPath
        );


    const std::string Url =
        ServerUrl +
        "file/" +
        Encoded;


    const fs::path Destination =
        fs::path(Normalized);


    const fs::path TempPath =
        Destination.string() +
        ".download";


    std::error_code ec;


    if (!Destination.parent_path().empty())
    {
        fs::create_directories(
            Destination.parent_path(),
            ec
        );

        if (ec)
        {
            std::cout
                << "Failed to create directory: "
                << Destination.parent_path()
                << '\n';

            return false;
        }
    }


    FileDownloader Downloader;

    if (!Downloader.DownloadFile(
            Url,
            Destination))
    {
        return false;
    }


    /*
        Здесь DownloadFile уже закончил запись
        во временный .download.

        Пока НЕ заменяем оригинал.

        Caller после этого дополнительно
        проверит SHA-256.
    */

    return true;
}


// ============================================================
// FileUpdater::Update
// ============================================================

bool FileUpdater::Update(
    const Manifest& Local,
    const Manifest& Remote,
    bool CfgOnly)
{
    size_t Updated = 0;


    for (const auto& [Path, RemoteEntry] :
         Remote)
    {
        if (!ShouldUpdate(
                Path,
                CfgOnly))
        {
            continue;
        }


        auto LocalIt =
            Local.find(Path);


        bool NeedsUpdate =
            false;


        if (LocalIt == Local.end())
        {
            NeedsUpdate = true;
        }
        else
        {
            if (ToLower(
                    LocalIt->second.Hash) !=
                ToLower(
                    RemoteEntry.Hash))
            {
                NeedsUpdate = true;
            }
        }


        if (!NeedsUpdate)
            continue;


        if (!UpdateFile(Path))
        {
            std::cout
                << "Failed to update: "
                << Path
                << '\n';

            return false;
        }


        const fs::path Destination =
            fs::path(Path);


        const fs::path TempPath =
            Destination.string() +
            ".download";


        /*
            Теперь проверяем SHA-256
            скачанного файла.

            Если hash не совпадает —
            оригинальный файл вообще
            не трогаем.
        */

        const std::string DownloadedHash =
            CalculateSHA256(
                TempPath
            );


        if (DownloadedHash.empty())
        {
            std::cout
                << "Failed to calculate hash: "
                << Path
                << '\n';

            std::error_code ec;

            fs::remove(
                TempPath,
                ec
            );

            return false;
        }


        if (ToLower(
                DownloadedHash) !=
            ToLower(
                RemoteEntry.Hash))
        {
            std::cout
                << "HASH MISMATCH: "
                << Path
                << '\n'
                << "Expected: "
                << RemoteEntry.Hash
                << '\n'
                << "Received: "
                << DownloadedHash
                << '\n';


            std::error_code ec;

            fs::remove(
                TempPath,
                ec
            );

            return false;
        }


        /*
            Hash совпал.

            Только теперь заменяем
            настоящий файл.
        */

        std::error_code ec;


        fs::remove(
            Destination,
            ec
        );


        ec.clear();


        fs::rename(
            TempPath,
            Destination,
            ec
        );


        if (ec)
        {
            std::cout
                << "Failed to replace file: "
                << Path
                << '\n'
                << "Error: "
                << ec.message()
                << '\n';

            return false;
        }


        ++Updated;


        std::cout
            << "[UPDATED] "
            << Path
            << '\n';
    }


    std::cout
        << "Updated: "
        << Updated
        << '\n';


    return true;
}


// ============================================================
// Delete untracked files
// ============================================================

bool FileUpdater::DeleteUntrackedFiles(
    const Manifest& ManifestData,
    bool CfgOnly)
{
    try
    {
        for (const auto& Entry :
             fs::recursive_directory_iterator(
                 ".",
                 fs::directory_options::
                     skip_permission_denied))
        {
            if (!Entry.is_regular_file())
                continue;


            const fs::path Path =
                Entry.path();


            if (IsExcluded(Path))
                continue;


            const bool Cfg =
                IsCfgFile(Path);


            if (CfgOnly && !Cfg)
                continue;


            if (!CfgOnly && Cfg)
                continue;


            const std::string RelativePath =
                NormalizePath(Path);


            if (ManifestData.find(
                    RelativePath) ==
                ManifestData.end())
            {
                std::cout
                    << "[DELETE] "
                    << RelativePath
                    << '\n';


                fs::remove(
                    Path
                );
            }
        }
    }
    catch (...)
    {
        return false;
    }


    return true;
}


// ============================================================
// Updater
// ============================================================

void Updater::SetServerUrl(const std::string& Url)
{
    ServerUrl = Url;

    if (!ServerUrl.empty() &&
        ServerUrl.back() != '/')
    {
        ServerUrl += '/';
    }

    ManifestUrl =
        ServerUrl + "manifest";

    CfgManifestUrl =
        ServerUrl + "manifest/cfg";

    std::cout
        << "Server URL set to: "
        << ServerUrl
        << '\n';
}


void Updater::PrintHelp()
{
    std::cout << R"(
============================================================
                        UPDATER
============================================================

Commands:

!help
    Show this help.

!scan
    Count non-CFG files.

!compare
    Download server Manifest.txt,
    generate local Manifest.txt,
    compare them.

!comparecfg
    Download server CfgManifest.txt,
    generate local CfgManifest.txt,
    compare them.

!update
    Update non-CFG files.

!updatecfg
    Update CFG files.

!scanupdate
    Scan -> compare -> update non-CFG files.

!scanupdatecfg
    Scan -> compare -> update CFG files.

!clean
    Delete untracked non-CFG files.

!seturl <url>
    Change the update server URL at runtime.

!exit
    Exit updater.

============================================================
)";
}


void Updater::PrintPrompt()
{
    std::cout
        << "\nUpdater> ";
}


// ============================================================
// Download remote manifest
// ============================================================

bool Updater::DownloadRemoteManifest(
    bool CfgOnly)
{
    if (CfgOnly)
    {
        return ManifestManager.DownloadManifest(
            CfgManifestUrl,
            RemoteCfgManifestPath
        );
    }


    return ManifestManager.DownloadManifest(
        ManifestUrl,
        RemoteManifestPath
    );
}


// ============================================================
// Generate local manifest
// ============================================================

bool Updater::GenerateLocalManifest(
    bool CfgOnly)
{
    if (CfgOnly)
    {
        return ManifestManager.GenerateCfgManifest();
    }


    return ManifestManager.GenerateNonCfgManifest();
}


// ============================================================
// Compare manifests
// ============================================================

bool Updater::CompareManifests(
    bool CfgOnly,
    ManifestCompareResult& OutResult)
{
    const fs::path LocalPath =
        CfgOnly
        ? LocalCfgManifestPath
        : LocalManifestPath;


    const fs::path RemotePath =
        CfgOnly
        ? RemoteCfgManifestPath
        : RemoteManifestPath;


    Manifest Local;
    Manifest Remote;


    if (!ManifestManager.LoadManifest(
            LocalPath,
            Local))
    {
        std::cout
            << "Failed to load local manifest.\n";

        return false;
    }


    if (!ManifestManager.LoadManifest(
            RemotePath,
            Remote))
    {
        std::cout
            << "Failed to load remote manifest.\n";

        return false;
    }


    OutResult =
        ManifestManager.Compare(
            Local,
            Remote
        );


    return true;
}


// ============================================================
// Print comparison
// ============================================================

void Updater::PrintCompareResult(
    const ManifestCompareResult& Result)
{
    std::cout
        << "\n"
        << "========================================\n";


    std::cout
        << "New files: "
        << Result.Added.size()
        << '\n';


    std::cout
        << "Modified files: "
        << Result.Modified.size()
        << '\n';


    std::cout
        << "Local-only files: "
        << Result.Missing.size()
        << '\n';


    std::cout
        << "Files requiring update: "
        << Result.GetDifferentCount()
        << '\n';


    if (!Result.Added.empty())
    {
        std::cout
            << "\n[NEW]\n";


        for (const auto& Path :
             Result.Added)
        {
            std::cout
                << "  + "
                << Path
                << '\n';
        }
    }


    if (!Result.Modified.empty())
    {
        std::cout
            << "\n[MODIFIED]\n";


        for (const auto& Path :
             Result.Modified)
        {
            std::cout
                << "  * "
                << Path
                << '\n';
        }
    }


    if (!Result.Missing.empty())
    {
        std::cout
            << "\n[LOCAL ONLY]\n";


        for (const auto& Path :
             Result.Missing)
        {
            std::cout
                << "  - "
                << Path
                << '\n';
        }
    }


    std::cout
        << "========================================\n";
}


// ============================================================
// !scan
// ============================================================

void Updater::Scan()
{
    std::cout
        << "Scanning non-CFG files...\n";


    const size_t Count =
        FileScanner.CountNonCfg();


    std::cout
        << "Non-CFG files: "
        << Count
        << '\n';
}


// ============================================================
// !compare
// ============================================================

void Updater::Compare()
{
    std::cout
        << "Downloading remote manifest...\n";


    if (!DownloadRemoteManifest(false))
    {
        std::cout
            << "Failed to download remote manifest.\n";

        return;
    }


    std::cout
        << "Generating local manifest...\n";


    if (!GenerateLocalManifest(false))
    {
        std::cout
            << "Failed to generate local manifest.\n";

        return;
    }


    ManifestCompareResult Result;


    if (!CompareManifests(
            false,
            Result))
    {
        return;
    }


    PrintCompareResult(Result);
}


// ============================================================
// !comparecfg
// ============================================================

void Updater::CompareCfg()
{
    std::cout
        << "Downloading remote CFG manifest...\n";


    if (!DownloadRemoteManifest(true))
    {
        std::cout
            << "Failed to download remote CFG manifest.\n";

        return;
    }


    std::cout
        << "Generating local CFG manifest...\n";


    if (!GenerateLocalManifest(true))
    {
        std::cout
            << "Failed to generate local CFG manifest.\n";

        return;
    }


    ManifestCompareResult Result;


    if (!CompareManifests(
            true,
            Result))
    {
        return;
    }


    PrintCompareResult(Result);
}


// ============================================================
// Common update
// ============================================================

void Updater::Update(
    bool CfgOnly)
{
    std::cout
        << "Downloading remote manifest...\n";


    if (!DownloadRemoteManifest(
            CfgOnly))
    {
        std::cout
            << "Failed to download remote manifest.\n";

        return;
    }


    std::cout
        << "Generating local manifest...\n";


    if (!GenerateLocalManifest(
            CfgOnly))
    {
        std::cout
            << "Failed to generate local manifest.\n";

        return;
    }


    const fs::path LocalPath =
        CfgOnly
        ? LocalCfgManifestPath
        : LocalManifestPath;


    const fs::path RemotePath =
        CfgOnly
        ? RemoteCfgManifestPath
        : RemoteManifestPath;


    Manifest Local;
    Manifest Remote;


    if (!ManifestManager.LoadManifest(
            LocalPath,
            Local))
    {
        return;
    }


    if (!ManifestManager.LoadManifest(
            RemotePath,
            Remote))
    {
        return;
    }


    ManifestCompareResult Result =
        ManifestManager.Compare(
            Local,
            Remote
        );


    PrintCompareResult(Result);


    if (Result.GetDifferentCount() == 0)
    {
        std::cout
            << "Everything is up to date.\n";

        return;
    }


    FileUpdater.Update(
        Local,
        Remote,
        CfgOnly
    );
}


// ============================================================
// !update
// ============================================================

void Updater::Update()
{
    Update(false);
}


// ============================================================
// !updatecfg
// ============================================================

void Updater::UpdateCfg()
{
    Update(true);
}


// ============================================================
// !scanupdate
// ============================================================

void Updater::ScanAndUpdate()
{
    std::cout
        << "Scanning non-CFG files...\n";


    std::cout
        << "Files found: "
        << FileScanner.CountNonCfg()
        << '\n';


    Update(false);
}


// ============================================================
// !scanupdatecfg
// ============================================================

void Updater::ScanAndUpdateCfg()
{
    std::cout
        << "Scanning CFG files...\n";


    std::cout
        << "Files found: "
        << FileScanner.CountCfg()
        << '\n';


    Update(true);
}


// ============================================================
// Confirmation
// ============================================================

bool Updater::AskConfirmation(
    const std::string& Question)
{
    std::cout
        << Question
        << " [y/N]: ";


    std::string Answer;


    std::getline(
        std::cin,
        Answer
    );


    Answer =
        Trim(Answer);


    if (Answer.empty())
        return false;


    return
        Answer[0] == 'y' ||
        Answer[0] == 'Y';
}


// ============================================================
// !clean
// ============================================================

void Updater::Clean()
{
    std::cout
        << "Downloading server manifest...\n";


    if (!DownloadRemoteManifest(false))
    {
        std::cout
            << "Failed to download manifest.\n";

        return;
    }


    Manifest Remote;


    if (!ManifestManager.LoadManifest(
            RemoteManifestPath,
            Remote))
    {
        return;
    }


    std::vector<std::string>
        FilesToDelete;


    try
    {
        for (const auto& Entry :
             fs::recursive_directory_iterator(
                 ".",
                 fs::directory_options::
                     skip_permission_denied))
        {
            if (!Entry.is_regular_file())
                continue;


            const fs::path Path =
                Entry.path();


            if (IsExcludedPath(Path))
                continue;


            if (IsCfgFile(Path))
                continue;


            const std::string RelativePath =
                NormalizePath(Path);


            if (RelativePath ==
                NormalizeManifestPath(
                    GeneratorPath.string()))
            {
                continue;
            }


            if (RelativePath ==
                NormalizeManifestPath(
                    LocalManifestPath.string()))
            {
                continue;
            }


            if (RelativePath ==
                NormalizeManifestPath(
                    RemoteManifestPath.string()))
            {
                continue;
            }


            if (Remote.find(
                    RelativePath) ==
                Remote.end())
            {
                FilesToDelete.push_back(
                    RelativePath
                );
            }
        }
    }
    catch (...)
    {
        std::cout
            << "Filesystem scan failed.\n";

        return;
    }


    if (FilesToDelete.empty())
    {
        std::cout
            << "No untracked files found.\n";

        return;
    }


    std::cout
        << "\nFiles that will be deleted:\n";


    for (const auto& Path :
         FilesToDelete)
    {
        std::cout
            << "  "
            << Path
            << '\n';
    }


    if (!AskConfirmation(
            "\nDelete these files?"))
    {
        std::cout
            << "Cancelled.\n";

        return;
    }


    size_t Deleted = 0;


    for (const auto& RelativePath :
         FilesToDelete)
    {
        try
        {
            if (fs::remove(
                    fs::path(RelativePath)))
            {
                ++Deleted;
            }
        }
        catch (...)
        {
            std::cout
                << "Failed to delete: "
                << RelativePath
                << '\n';
        }
    }


    std::cout
        << "Deleted: "
        << Deleted
        << '\n';
}


// ============================================================
// Command loop
// ============================================================

void Updater::Run()
{
    PrintHelp();


    std::string Command;


    while (true)
    {
        PrintPrompt();


        if (!std::getline(
                std::cin,
                Command))
        {
            break;
        }


        Command =
            Trim(Command);


        if (Command.empty())
            continue;


        if (Command == "!help")
        {
            PrintHelp();
        }
        else if (Command == "!scan")
        {
            Scan();
        }
        else if (Command == "!compare")
        {
            Compare();
        }
        else if (Command == "!comparecfg")
        {
            CompareCfg();
        }
        else if (Command == "!update")
        {
            Update();
        }
        else if (Command == "!updatecfg")
        {
            UpdateCfg();
        }
        else if (Command == "!scanupdate")
        {
            ScanAndUpdate();
        }
        else if (Command == "!scanupdatecfg")
        {
            ScanAndUpdateCfg();
        }
        else if (Command == "!clean")
        {
            Clean();
        }
        else if (Command.rfind("!seturl ", 0) == 0)
        {
            SetServerUrl(
                Trim(Command.substr(8))
            );
        }
        else if (Command == "!seturl")
        {
            std::cout
                << "Usage: !seturl <url>\n";
        }
        else if (Command == "!exit")
        {
            break;
        }
        else
        {
            std::cout
                << "Unknown command: "
                << Command
                << '\n';
        }
    }
}


// ============================================================
// Entry point
// ============================================================

int main()
{
    Updater UpdaterInstance;

    UpdaterInstance.Run();

    return 0;
}