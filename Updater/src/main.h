#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include <cstdint>
#include <functional>

namespace fs = std::filesystem;


// ============================================================
// Manifest
// ============================================================

struct ManifestEntry
{
    std::string Path;
    uintmax_t Size = 0;
    std::string Hash;
};

using Manifest =
    std::unordered_map<
        std::string,
        ManifestEntry
    >;


// ============================================================
// File information
// ============================================================

struct FileInfo
{
    fs::path Path;
    uintmax_t Size = 0;
    std::string Hash;
};


// ============================================================
// Compare result
// ============================================================

struct ManifestCompareResult
{
    std::vector<std::string> Added;
    std::vector<std::string> Modified;
    std::vector<std::string> Missing;

    size_t GetDifferentCount() const
    {
        return Added.size() + Modified.size();
    }
};


// ============================================================
// Generator process
// ============================================================

class GeneratorProcess
{
public:

    bool RunCommand(
        const fs::path& Executable,
        const std::string& Command
    );

private:

    bool CreatePipes();

    void ClosePipes();

private:

    void* ProcessHandle = nullptr;
    void* ThreadHandle = nullptr;

    void* StdInRead = nullptr;
    void* StdInWrite = nullptr;

    void* StdOutRead = nullptr;
    void* StdOutWrite = nullptr;
};


// ============================================================
// Manifest Manager
// ============================================================

class ManifestManager
{
public:

    bool DownloadManifest(
        const std::string& Url,
        const fs::path& OutputPath
    );

    bool GenerateCfgManifest();

    bool GenerateNonCfgManifest();

    bool GenerateBothManifests();

    bool LoadManifest(
        const fs::path& Path,
        Manifest& OutManifest
    ) const;

    ManifestCompareResult Compare(
        const Manifest& Local,
        const Manifest& Remote
    ) const;

    size_t CountFiles(
        const Manifest& ManifestData
    ) const;
};


// ============================================================
// File Scanner
// ============================================================

class FileScanner
{
public:

    std::vector<FileInfo> ScanAll() const;

    std::vector<FileInfo> ScanCfg() const;

    std::vector<FileInfo> ScanNonCfg() const;

    size_t CountAll() const;

    size_t CountCfg() const;

    size_t CountNonCfg() const;

private:

    bool IsCfgFile(
        const fs::path& Path
    ) const;

    bool IsExcluded(
        const fs::path& Path
    ) const;

    std::vector<std::string>
    LoadCfgExtensions() const;

    std::vector<std::string>
    LoadExcludedPaths() const;
};


// ============================================================
// File Downloader
// ============================================================

class FileDownloader
{
public:

    using ProgressCallback =
        std::function<void(
            uintmax_t Downloaded,
            uintmax_t Total
        )>;

public:

    FileDownloader();

    bool DownloadFile(
        const std::string& Url,
        const fs::path& Destination
    );

    bool DownloadFiles(
        const std::vector<std::string>& Paths
    );

    void SetProgressCallback(
        ProgressCallback Callback
    );

private:

    ProgressCallback Progress;
};


// ============================================================
// File Updater
// ============================================================

class FileUpdater
{
public:

    FileUpdater();

    bool Update(
        const Manifest& Local,
        const Manifest& Remote,
        bool CfgOnly
    );

    bool UpdateFile(
        const std::string& RelativePath
    );

    bool DeleteUntrackedFiles(
        const Manifest& ManifestData,
        bool CfgOnly
    );

private:

    bool ShouldUpdate(
        const std::string& RelativePath,
        bool CfgOnly
    ) const;

    bool IsExcluded(
        const fs::path& Path
    ) const;

    void PrintOverallProgress(
        uintmax_t Downloaded,
        uintmax_t Total
    );

private:

    FileDownloader Downloader;

    uintmax_t TotalBytes = 0;
    uintmax_t CompletedBytes = 0;
    uintmax_t CurrentFileDownloaded = 0;
};


// ============================================================
// Updater
// ============================================================

class Updater
{
public:

    Updater();

    void Run();

    void SetServerUrl(
        const std::string& Url
    );

private:

    void PrintHelp();

    void PrintPrompt();

    void Scan();

    void Compare();

    void CompareCfg();

    void Update();

    void UpdateCfg();

    void ScanAndUpdate();

    void ScanAndUpdateCfg();

    void Clean();

    void Update(
        bool CfgOnly
    );

    bool DownloadRemoteManifest(
        bool CfgOnly
    );

    bool GenerateLocalManifest(
        bool CfgOnly
    );

    bool CompareManifests(
        bool CfgOnly,
        ManifestCompareResult& OutResult
    );

    bool UpdateFiles(
        bool CfgOnly
    );

    void PrintCompareResult(
        const ManifestCompareResult& Result
    );

    bool AskConfirmation(
        const std::string& Question
    );

private:

    ManifestManager ManifestManager;

    FileScanner FileScanner;

    FileUpdater FileUpdater;


    // ========================================================
    // Paths
    // ========================================================

    fs::path RootPath = ".";

    fs::path GeneratorPath =
        "ManifestGenerator.exe";

    fs::path LocalManifestPath =
        "Manifest.txt";

    fs::path LocalCfgManifestPath =
        "CfgManifest.txt";

    fs::path RemoteManifestPath =
        "RemoteManifest.txt";

    fs::path RemoteCfgManifestPath =
        "RemoteCfgManifest.txt";

    fs::path CfgFilesPath =
        "CfgFiles.cfg";

    fs::path CfgExtensionsPath =
        "CfgExtensions.cfg";

    fs::path NonCfgFilesPath =
        "NonCfgFiles.cfg";

    fs::path ExcludedPathsPath =
        "ExcludedPaths.cfg";


    // ========================================================
    // Server
    // ========================================================

    std::string ServerUrl =
        "http://89.28.48.2:8080/";

    std::string ManifestUrl =
        ServerUrl + "manifest";

    std::string CfgManifestUrl =
        ServerUrl + "manifest/cfg";
};
