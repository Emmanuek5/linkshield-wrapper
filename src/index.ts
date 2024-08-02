import type { ResponseBody, DetailedResponseBody, DynamicAnalysisResponse, DomainSimilarityResponse } from "./types/response";
import { promises as fs } from "fs";
/**
 * The LinkShield class.
 * @class LinkShield
 * 
 * Used for interacting with the LinkShield API.
 * @example new LinkShield ({ apiKey: "API_KEY", cacheFile: "cache.json" })
 * @example linkShield.checkUrl("https://example.com")
 * @example linkShield.getDetailedCheck("https://example.com")
 * @example linkShield.performDynamicAnalysis("https://example.com")
 * @example linkShield.checkDomainSimilarity("example.com")
 * @example linkShield.getScreenshotUrl("screenshot.png")
 *  
 */
class LinkShield {
    private apiKey: string;
    private cacheFile: string;
    private baseEndpoint = "https://api.linkshieldai.com";
    private cache: { [url: string]: ResponseBody | DetailedResponseBody | DynamicAnalysisResponse | DomainSimilarityResponse[] } = {};

    /**
     * Creates an instance of LinkShield.
     * @param apiKey - The API Key for the LinkShield API.
     * @param cacheFile - The file to store the cache.
     * @example new LinkShield ({ apiKey: "API_KEY", cacheFile: "cache.json" })
     */
    constructor({ apiKey, cacheFile }: { apiKey: string, cacheFile: string }) {
        this.apiKey = apiKey;
        this.cacheFile = cacheFile;
        this.loadCache();
    }

    /**
     * Loads the cache from the cache file.
     * @returns The promise of the cache being loaded.
     */
    private async loadCache(): Promise<void> {
        try {
            const data = await fs.readFile(this.cacheFile, "utf8");
            this.cache = JSON.parse(data);
        } catch (err) {
            console.error("Error loading cache:", err);
        }
    }

    /**
     * Saves the cache to the cache file.
     * @returns The promise of the cache being saved.
     */
    private async saveCache(): Promise<void> {
        try {
            await fs.writeFile(this.cacheFile, JSON.stringify(this.cache), "utf8");
        } catch (err) {
            console.error("Error saving cache:", err);
        }
    }

    /**
     * Maps the result string or array to a numerical value.
     * @param result - The result from the API.
     * @returns The numerical value corresponding to the result.
     * @example this.mapResultToNumber("Likely safe")
     * 
     */
    private mapResultToNumber(result: string | string[]): number {
        if (Array.isArray(result)) {
            return 1; // If it's an array of detections, consider it malicious
        }

        switch (result) {
            case "Likely safe":
            case "Safe":
                return 0;
            case "The system didn't detect anything malicious.":
                return 0.5;
            case "Might be malicious":
                return 1;
            default:
                return -1; // Undefined or error
        }
    }

    /**
     * Checks if a URL is a phishing link.
     * @param url - The URL to check.
     * @returns The result of the URL check as a numerical value.
     * @example
     * ```ts
     * const check = await linkShield.checkUrl("https://example.com");
     * console.log(check);
     * ```
     */
    async checkUrl(url: string): Promise<number> {
        if (this.cache[url]) {
            return this.mapResultToNumber((this.cache[url] as ResponseBody).result || "");
        }

        const response = await fetch(`${this.baseEndpoint}/?key=${this.apiKey}&url=${url}`);
        const data: ResponseBody = await response.json();

        this.cache[url] = data;
        await this.saveCache();

        return this.mapResultToNumber(data.result || "");
    }

    /**
     * Gets detailed information about a URL.
     * @param url - The URL to get detailed information about.
     * @returns The detailed result of the URL check.
     * @example
     * ```ts
     * const detailedCheck = await linkShield.getDetailedCheck("https://example.com");
     * 
     * console.log(detailedCheck);
     * 
     * ```
     */
    async getDetailedCheck(url: string): Promise<DetailedResponseBody> {
        const cacheKey = `${url}_detailed`;

        if (this.cache[cacheKey]) {
            return this.cache[cacheKey] as DetailedResponseBody;
        }

        const response = await fetch(`${this.baseEndpoint}/classify_link?key=${this.apiKey}&url=${url}`);
        const data: DetailedResponseBody = await response.json();

        this.cache[cacheKey] = data;
        await this.saveCache();

        return data;
    }

    /**
     * Retrieves the URL of a screenshot.
     * @param fileName - The file name of the screenshot to retrieve.
     * @returns The URL of the screenshot.
     * @example linkShield.getScreenshotUrl("screenshot.png")
     */
    getScreenshotUrl(fileName: string): string {
        return `${this.baseEndpoint}/screenshot/${fileName}`;
    }

    /**
     * Performs dynamic analysis on a URL.
     * @param url - The URL to perform dynamic analysis on.
     * @returns The result of the dynamic analysis as a numerical value.
     * @example 
     * ```ts
     * const dynamicAnalysisResult = await linkShield.performDynamicAnalysis("https://example.com");
     * console.log(dynamicAnalysisResult);
     * ```
     */
    async performDynamicAnalysis(url: string): Promise<number> {
        const encodedUrl = Buffer.from(url).toString('base64');
        const dynamicAnalysisUrl = `https://api.vladhog.ru/security/dynamic_analysis/${encodedUrl}`;

        if (this.cache[dynamicAnalysisUrl]) {
            return this.mapResultToNumber((this.cache[dynamicAnalysisUrl] as DynamicAnalysisResponse).result);
        }

        const response = await fetch(dynamicAnalysisUrl);
        const data: DynamicAnalysisResponse = await response.json();

        this.cache[dynamicAnalysisUrl] = data;
        await this.saveCache();

        if (data.response !== "200") {
            return -1; // Error code
        }

        return this.mapResultToNumber(data.result);
    }

    /**
     * Checks domain similarity.
     * @param domain - The domain to check similarity.
     * @returns The domain similarity response.
     * 
     * @example
     * ```ts
     * const domainSimilarity = await linkShield.checkDomainSimilarity("example.com");
     * console.log(domainSimilarity);
     * ```
     */
    async checkDomainSimilarity(domain: string): Promise<DomainSimilarityResponse[]> {
        const domainSimilarityUrl = `https://api.vladhog.ru/security/domain_similarity/${domain}`;

        if (this.cache[domainSimilarityUrl]) {
            return this.cache[domainSimilarityUrl] as DomainSimilarityResponse[];
        }

        const response = await fetch(domainSimilarityUrl);
        const data: DomainSimilarityResponse[] = await response.json();

        this.cache[domainSimilarityUrl] = data;
        await this.saveCache();

        return data;
    }
}

export default LinkShield;