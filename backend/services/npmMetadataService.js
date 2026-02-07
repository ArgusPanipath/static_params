/**
 * NPM Metadata Service
 *
 * Fetches package metadata from the npm CouchDB registry replica
 * to provide context for rules 9-32
 */

const axios = require("axios");

const NPM_REGISTRY_URL = "https://replicate.npmjs.com/registry";
const REQUEST_TIMEOUT = 10000; // 10 seconds

class NpmMetadataService {
  /**
   * Fetch complete package document from npm registry
   */
  async getPackageMetadata(packageName) {
    try {
      const response = await axios.get(`${NPM_REGISTRY_URL}/${packageName}`, {
        timeout: REQUEST_TIMEOUT
      });
      return response.data;
    } catch (error) {
      if (error.response?.status === 404) {
        throw new Error(`Package "${packageName}" not found in registry`);
      }
      throw new Error(`Failed to fetch package metadata: ${error.message}`);
    }
  }

  /**
   * Extract and normalize data for security analysis
   */
  extractAnalysisData(packageDoc) {
    const latestVersion =
      packageDoc["dist-tags"]?.latest ||
      Object.keys(packageDoc.versions || {}).pop();

    const versionData = packageDoc.versions?.[latestVersion] || {};
    const allVersions = Object.keys(packageDoc.versions || {});

    return {
      // Basic identification
      packageName: packageDoc.name,
      latestVersion,
      description: packageDoc.description || versionData.description || "",

      // README content (critical for rule 10)
      readme: packageDoc.readme || versionData.readme || "",

      // Version history (for rules 9, 24, 25, 30)
      versionHistory: allVersions
        .map(version => ({
          version,
          publishedAt: packageDoc.time?.[version],
          dependencies: packageDoc.versions[version].dependencies || {},
          devDependencies: packageDoc.versions[version].devDependencies || {},
          scripts: packageDoc.versions[version].scripts || {},
          license: packageDoc.versions[version].license
        }))
        .sort((a, b) => new Date(a.publishedAt) - new Date(b.publishedAt)),

      // Temporal data (for rules 9, 24)
      publishTimeline: packageDoc.time || {},
      createdAt: packageDoc.time?.created,
      modifiedAt: packageDoc.time?.modified,

      // Current version details
      packageJson: {
        name: packageDoc.name,
        version: latestVersion,
        description: versionData.description,
        main: versionData.main,
        scripts: versionData.scripts || {},
        dependencies: versionData.dependencies || {},
        devDependencies: versionData.devDependencies || {},
        license: versionData.license,
        repository: versionData.repository,
        homepage: versionData.homepage,
        keywords: versionData.keywords || []
      },

      // Maintainer info (for rule 24)
      maintainers: packageDoc.maintainers || [],
      author: versionData.author,

      // Repository info (for rule 28)
      repository: versionData.repository,
      homepage: versionData.homepage,
      bugs: versionData.bugs,

      // Distribution info
      tarball: versionData.dist?.tarball,
      shasum: versionData.dist?.shasum,
      packageSize: versionData.dist?.unpackedSize,

      // Technical indicators
      hasNativeCode: !!(
        versionData.gypfile ||
        versionData.binary ||
        versionData.scripts?.install?.includes("node-gyp")
      ),

      // Download statistics (if available)
      downloads: packageDoc.downloads || null
    };
  }

  /**
   * Get recent changes from the registry (for monitoring)
   */
  async getRecentChanges(limit = 100, since = null) {
    try {
      const params = {
        limit,
        include_docs: true
      };

      if (since) {
        params.since = since;
      }

      const response = await axios.get(`${NPM_REGISTRY_URL}/_changes`, {
        params,
        timeout: REQUEST_TIMEOUT
      });

      return response.data;
    } catch (error) {
      throw new Error(`Failed to fetch changes: ${error.message}`);
    }
  }

  /**
   * Fetch GitHub statistics for a package (for rule 28)
   */
  async getGitHubStats(repositoryUrl) {
    if (!repositoryUrl) return null;

    try {
      // Extract owner/repo from various GitHub URL formats
      const match = repositoryUrl.match(/github\.com[/:]([\w-]+)\/([\w-]+)/);
      if (!match) return null;

      const [, owner, repo] = match;
      const apiUrl = `https://api.github.com/repos/${owner}/${repo}`;

      const response = await axios.get(apiUrl, {
        timeout: REQUEST_TIMEOUT,
        headers: {
          Accept: "application/vnd.github.v3+json"
          // Add GitHub token if available: 'Authorization': `token ${process.env.GITHUB_TOKEN}`
        }
      });

      return {
        stars: response.data.stargazers_count,
        forks: response.data.forks_count,
        watchers: response.data.watchers_count,
        openIssues: response.data.open_issues_count,
        createdAt: response.data.created_at,
        updatedAt: response.data.updated_at,
        pushedAt: response.data.pushed_at
      };
    } catch (error) {
      console.warn(`Failed to fetch GitHub stats: ${error.message}`);
      return null;
    }
  }

  /**
   * Fetch weekly download count (for rule 28)
   */
  async getWeeklyDownloads(packageName) {
    if (!packageName) return 0;

    try {
      const encoded = encodeURIComponent(packageName);
      const url = `https://api.npmjs.org/downloads/point/last-week/${encoded}`;
      const response = await axios.get(url, { timeout: REQUEST_TIMEOUT });
      return response.data?.downloads ?? 0;
    } catch (error) {
      console.warn(`Failed to fetch weekly downloads: ${error.message}`);
      return 0;
    }
  }

  /**
   * Get popular packages list (for rule 23 - typosquatting)
   */
  async getPopularPackages(limit = 1000) {
    // In production, this would query npm's download stats API
    // For now, return a static list or cache
    // You can populate this from: https://api.npmjs.org/downloads/top

    try {
      await axios.get(`https://api.npmjs.org/downloads/range/last-week`, {
        timeout: REQUEST_TIMEOUT
      });

      // This is a placeholder - actual implementation depends on npm API
      return [
        "react",
        "vue",
        "angular",
        "express",
        "lodash",
        "axios",
        "webpack",
        "typescript",
        "eslint",
        "jest"
        // ... would be populated dynamically
      ];
    } catch (error) {
      console.warn("Failed to fetch popular packages, using fallback list");
      return [
        "react",
        "vue",
        "angular",
        "express",
        "lodash",
        "axios",
        "webpack",
        "typescript",
        "eslint",
        "jest"
      ];
    }
  }

  /**
   * Download package tarball and extract files (for complete analysis)
   */
  async downloadPackageFiles(tarballUrl) {
    // This would download the .tgz file and extract it
    // Implementation depends on whether you want to analyze actual files
    // or just use metadata

    // For now, return placeholder
    console.warn("Package file download not implemented - using metadata only");
    return {
      files: [],
      message: "File analysis requires tarball download implementation"
    };
  }
}

module.exports = new NpmMetadataService();
