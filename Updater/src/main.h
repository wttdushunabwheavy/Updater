#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include <cstdint>

namespace fs = std::filesystem;


// ============================================================
// Manifest
// ============================================================

struct ManifestEntry
{
    std::string Path;
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

    // --------------------------------------------------------
    // Remote manifest
    // --------------------------------------------------------

    bool DownloadManifest(
        const std::string& Url,
        const fs::path& OutputPath
    );

    // --------------------------------------------------------
    // Local manifest generation
    // --------------------------------------------------------

    bool GenerateCfgManifest();

    bool GenerateNonCfgManifest();

    bool GenerateBothManifests();

    // --------------------------------------------------------
    // Manifest loading
    // --------------------------------------------------------

    bool LoadManifest(
        const fs::path& Path,
        Manifest& OutManifest
    ) const;

    // --------------------------------------------------------
    // Manifest comparison
    // --------------------------------------------------------

    ManifestCompareResult Compare(
        const Manifest& Local,
        const Manifest& Remote
    ) const;

    // --------------------------------------------------------
    // Helpers
    // --------------------------------------------------------

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

    // --------------------------------------------------------
    // General scan
    // --------------------------------------------------------

    std::vector<FileInfo> ScanAll() const;

    std::vector<FileInfo> ScanCfg() const;

    std::vector<FileInfo> ScanNonCfg() const;

    // --------------------------------------------------------
    // Count
    // --------------------------------------------------------

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

    bool DownloadFile(
        const std::string& Url,
        const fs::path& Destination
    );

    bool DownloadFiles(
        const std::vector<std::string>& Paths
    );
};


// ============================================================
// File Updater
// ============================================================

class FileUpdater
{
public:

    // --------------------------------------------------------
    // Update
    // --------------------------------------------------------

    bool Update(
        const Manifest& Local,
        const Manifest& Remote,
        bool CfgOnly
    );

    // --------------------------------------------------------
    // Update individual files
    // --------------------------------------------------------

    bool UpdateFile(
        const std::string& RelativePath
    );

    // --------------------------------------------------------
    // Delete untracked files
    // --------------------------------------------------------

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
};


// ============================================================
// Updater
// ============================================================

class Updater
{
public:

    void Run();
    
    void SetServerUrl(const std::string& Url);
    
private:

    // ========================================================
    // Console
    // ========================================================

    void PrintHelp();

    void PrintPrompt();

    // ========================================================
    // Commands
    // ========================================================

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

    // ========================================================
    // Common operations
    // ========================================================

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

    // ========================================================
    // Utilities
    // ========================================================

    void PrintCompareResult(
        const ManifestCompareResult& Result
    );

    bool AskConfirmation(
        const std::string& Question
    );

private:

    // ========================================================
    // Components
    // ========================================================

    ManifestManager ManifestManager;

    FileScanner FileScanner;

    FileDownloader FileDownloader;

    FileUpdater FileUpdater;


    // ========================================================
    // Paths
    // ========================================================

    fs::path RootPath = ".";

    fs::path GeneratorPath =
        "ManifestGenerator.exe";


    // --------------------------------------------------------
    // Local manifests
    // --------------------------------------------------------

    fs::path LocalManifestPath =
        "Manifest.txt";

    fs::path LocalCfgManifestPath =
        "CfgManifest.txt";


    // --------------------------------------------------------
    // Downloaded remote manifests
    // --------------------------------------------------------

    fs::path RemoteManifestPath =
        "RemoteManifest.txt";

    fs::path RemoteCfgManifestPath =
        "RemoteCfgManifest.txt";


    // ========================================================
    // Generator configuration
    // ========================================================

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
        "http://127.0.0.1:8080/";

    std::string ManifestUrl =
        ServerUrl + "manifest";

    std::string CfgManifestUrl =
        ServerUrl + "manifest/cfg";
};