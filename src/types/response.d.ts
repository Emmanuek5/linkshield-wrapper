/**
 * The response body.
 * @property result - The result.
 * @property Error - The error.
 *  
 * @example
 * ```ts
 * 
 */
export interface ResponseBody {
    result?: string;
    Error?: string;
}

/**
 * The detailed response body.
 * @property "screenshot url" - The screenshot URL.
 * @property tag - The tag.
 * @example
 * ```ts
 * {
 *   "screenshot url": "https://example.com/screenshot.png",
 *  tag: "phishing"
 * }
 * ```
 */
export interface DetailedResponseBody extends ResponseBody {
    "screenshot url"?: string;
    tag?: string;
}
/**
 * The dynamic analysis response.
 * @property response - The response.
 * @property reason - The reason.
 * @property result - The result.
 * @example
 * ```ts
 * {
 *    response: "success",
 *   result: "clean"
 * }
 * ```
 * */
export interface DynamicAnalysisResponse {
    response: string;
    reason?: string;
    result: string | string[];
}

/**
 * The domain similarity response.
 * @property similar_to - The domain that the input domain is similar to.
 * @property similarity_percent - The similarity percentage.
 * 
 * @example
 * ```ts
 * {
 *   similar_to: "example.com",
 *  similarity_percent: 0.8
 * }
 */
export interface DomainSimilarityResponse {
    similar_to: string;
    similarity_percent: number;
}