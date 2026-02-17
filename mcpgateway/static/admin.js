// Make URL field read-only for integration type MCP
function updateEditToolUrl() {
    const editTypeField = document.getElementById("edit-tool-type");
    const editurlField = document.getElementById("edit-tool-url");
    if (editTypeField && editurlField) {
        if (editTypeField.value === "MCP") {
            editurlField.readOnly = true;
        } else {
            editurlField.readOnly = false;
        }
    }
}

window.openCreateRoleModal = function () {
    const modal = document.getElementById("rbac-create-role-modal");
    if (!modal) return;

    modal.classList.remove("hidden");
    modal.style.display = "block";

    // Reset status
    const status = document.getElementById("rbac-create-role-status");
    if (status) {
        status.textContent = "";
        status.className = "text-sm";
    }

    // IMPORTANT: load permissions now
    if (typeof window.loadRolePermissionsChecklist === "function") {
        window.loadRolePermissionsChecklist();
    } else {
        console.warn("loadRolePermissionsChecklist not defined");
    }
};


window.closeCreateRoleModal = function () {
    console.log("✅ closeCreateRoleModal CALLED");
    const modal = document.getElementById("rbac-create-role-modal");
    if (!modal) return;
    modal.classList.add("hidden");
    modal.style.display = "none";
};

// ===============================
// RBAC – Load permissions checklist
// ===============================
window.loadRolePermissionsChecklist = async function () {
    const container = document.getElementById("rbac-role-permissions");
    if (!container) {
        console.error("rbac-role-permissions container not found");
        return;
    }

    container.innerHTML =
        `<div class="text-gray-500 dark:text-gray-400">Loading permissions...</div>`;

    try {
        const headers = await rbacHeaders();

        const resp = await fetchWithTimeout(
            `${window.ROOT_PATH}/rbac/permissions/available`,
            { headers }
        );

        if (!resp.ok) {
            const err = await safeJson(resp);
            throw new Error(err?.detail || `Failed to load permissions`);
        }

        const data = await resp.json();

        if (!data.permissions_by_resource) {
            throw new Error("Invalid permissions response");
        }

        // Render grouped permissions
        container.innerHTML = Object.entries(data.permissions_by_resource)
            .map(([resource, perms]) => `
                <div class="mb-3">
                  <div class="text-xs font-semibold uppercase text-gray-500 dark:text-gray-400 mb-1">
                    ${escapeHtml(resource)}
                  </div>
                  <div class="space-y-1">
                    ${perms.map(p => `
                      <label class="flex items-center gap-2 text-sm text-gray-800 dark:text-gray-200">
                        <input
                          type="checkbox"
                          class="rbac-role-permission h-4 w-4 rounded border-gray-300 text-indigo-600
                                 focus:ring-indigo-500 dark:bg-gray-800 dark:border-gray-600"
                          value="${escapeHtml(p)}"
                        />
                        <span class="font-mono text-xs">${escapeHtml(p)}</span>
                      </label>
                    `).join("")}
                  </div>
                </div>
            `)
            .join("");
    } catch (e) {
        console.error("Failed to load permissions:", e);
        container.innerHTML =
            `<div class="text-red-600 text-sm">${escapeHtml(e.message)}</div>`;
    }
};


// RBAC global state (must exist before any RBAC function runs)
window.__rbacState = window.__rbacState || {
  initialized: false,
  myPermissions: [],
  canUserManage: false,
  canAudit: false,
  rolesCache: [],
  allPermissionsCache: null,

  // ✅ new for My Access UI
  roleNameMap: {},          // { role_id: role_name }
  myPermissionsList: [],    // latest perms list for search
};



// Attach event listener after DOM is loaded or when modal opens
document.addEventListener("DOMContentLoaded", function () {
    const TypeField = document.getElementById("edit-tool-type");
    if (TypeField) {
        TypeField.addEventListener("change", updateEditToolUrl);
        // Set initial state
        updateEditToolUrl();
    }

});
/**
 * ====================================================================
 * SECURE ADMIN.JS - COMPLETE VERSION WITH XSS PROTECTION
 * ====================================================================
 *
 * SECURITY FEATURES:
 * - XSS prevention with comprehensive input sanitization
 * - Input validation for all form fields
 * - Safe DOM manipulation only
 * - No innerHTML usage with user data
 * - Comprehensive error handling and timeouts
 *
 * PERFORMANCE FEATURES:
 * - Centralized state management
 * - Memory leak prevention
 * - Proper event listener cleanup
 * - Race condition elimination
 */

// ===================================================================
// SECURITY: HTML-escape function to prevent XSS attacks
// ===================================================================

function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) {
        return "";
    }
    return String(unsafe)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;")
        .replace(/`/g, "&#x60;")
        .replace(/\//g, "&#x2F;"); // Extra protection against script injection
}

// Escape a string so it is safe to embed inside single-quoted JS strings in HTML attributes.
function escapeJs(value) {
    const s = String(value ?? "");
    return s
        .replace(/\\/g, "\\\\")
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\"')
        .replace(/\n/g, "\\n")
        .replace(/\r/g, "\\r")
        .replace(/\t/g, "\\t")
        // prevent "</script>" / HTML context issues too
        .replace(/</g, "\\u003C")
        .replace(/>/g, "\\u003E");
}

/**
 * Header validation constants and functions
 */
const HEADER_NAME_REGEX = /^[A-Za-z0-9-]+$/;
const MAX_HEADER_VALUE_LENGTH = 4096;

/**
 * Validate a passthrough header name and value
 * @param {string} name - Header name to validate
 * @param {string} value - Header value to validate
 * @returns {Object} Validation result with 'valid' boolean and 'error' message
 */
function validatePassthroughHeader(name, value) {
    // Validate header name
    if (!HEADER_NAME_REGEX.test(name)) {
        return {
            valid: false,
            error: `Header name "${name}" contains invalid characters. Only letters, numbers, and hyphens are allowed.`,
        };
    }

    // Check for dangerous characters in value
    if (value.includes("\n") || value.includes("\r")) {
        return {
            valid: false,
            error: "Header value cannot contain newline characters",
        };
    }

    // Check value length
    if (value.length > MAX_HEADER_VALUE_LENGTH) {
        return {
            valid: false,
            error: `Header value too long (${value.length} chars, max ${MAX_HEADER_VALUE_LENGTH})`,
        };
    }

    // Check for control characters (except tab)
    const hasControlChars = Array.from(value).some((char) => {
        const code = char.charCodeAt(0);
        return code < 32 && code !== 9; // Allow tab (9) but not other control chars
    });

    if (hasControlChars) {
        return {
            valid: false,
            error: "Header value contains invalid control characters",
        };
    }

    return { valid: true };
}

/**
 * SECURITY: Validate input names to prevent XSS and ensure clean data
 */
function validateInputName(name, type = "input") {
    const rawType = String(type || "input").trim();
    const lowerType = rawType.toLowerCase();
    const titledType = rawType.charAt(0).toUpperCase() + rawType.slice(1);
    const hasSpecificFieldWord =
        /(name|uri|url|id|identifier|property|parameter)/i.test(rawType);
    const subject =
        lowerType === "name"
            ? "Name"
            : hasSpecificFieldWord
              ? titledType
              : `${titledType} name`;

    if (!name || typeof name !== "string") {
        return { valid: false, error: `${subject} is required` };
    }

    // Remove any HTML tags
    const cleaned = name.replace(/<[^>]*>/g, "");

    // Check for dangerous patterns
    const dangerousPatterns = [
        /<script/i,
        /javascript:/i,
        /on\w+\s*=/i,
        /data:text\/html/i,
        /vbscript:/i,
    ];

    for (const pattern of dangerousPatterns) {
        if (pattern.test(name)) {
            return {
                valid: false,
                error: `${subject} contains invalid characters`,
            };
        }
    }

    // Length validation
    if (cleaned.length < 1) {
        return { valid: false, error: `${subject} cannot be empty` };
    }

    if (cleaned.length > window.MAX_NAME_LENGTH) {
        return {
            valid: false,
            error: `${subject} must be ${window.MAX_NAME_LENGTH} characters or less`,
        };
    }

    // For prompt names, be more restrictive
    if (type === "prompt") {
        // Only allow alphanumeric, underscore, hyphen, and spaces
        const validPattern = /^[a-zA-Z0-9_\s-]+$/;
        if (!validPattern.test(cleaned)) {
            return {
                valid: false,
                error: "Prompt name can only contain letters, numbers, spaces, underscores, and hyphens",
            };
        }
    }

    return { valid: true, value: cleaned };
}

/**
 * Extracts content from various formats with fallback
 */
function extractContent(content, fallback = "") {
    if (typeof content === "object" && content !== null) {
        if (content.text !== undefined && content.text !== null) {
            return content.text;
        } else if (content.blob !== undefined && content.blob !== null) {
            return content.blob;
        } else if (content.content !== undefined && content.content !== null) {
            return content.content;
        } else {
            return JSON.stringify(content, null, 2);
        }
    }
    return String(content || fallback);
}

/**
 * SECURITY: Validate URL inputs
 */
function validateUrl(url) {
    if (!url || typeof url !== "string") {
        return { valid: false, error: "URL is required" };
    }

    try {
        const urlObj = new URL(url);
        const allowedProtocols = ["http:", "https:"];

        if (!allowedProtocols.includes(urlObj.protocol)) {
            return {
                valid: false,
                error: "Only HTTP and HTTPS URLs are allowed",
            };
        }

        return { valid: true, value: url };
    } catch (error) {
        return { valid: false, error: "Invalid URL format" };
    }
}

/**
 * SECURITY: Validate JSON input
 */
function validateJson(jsonString, fieldName = "JSON") {
    if (!jsonString || !jsonString.trim()) {
        return { valid: true, value: {} }; // Empty is OK, defaults to empty object
    }

    try {
        const parsed = JSON.parse(jsonString);
        return { valid: true, value: parsed };
    } catch (error) {
        return {
            valid: false,
            error: `Invalid ${fieldName} format: ${error.message}`,
        };
    }
}

/**
 * SECURITY: Safely set innerHTML ONLY for trusted backend content
 * For user-generated content, use textContent instead
 */
function safeSetInnerHTML(element, htmlContent, isTrusted = false) {
    if (!isTrusted) {
        console.error("Attempted to set innerHTML with untrusted content");
        element.textContent = htmlContent; // Fallback to safe text
        return;
    }
    element.innerHTML = htmlContent;
}

// ===================================================================
// UTILITY FUNCTIONS - Define these FIRST before anything else
// ===================================================================

// Check for inative items
function isInactiveChecked(type) {
    const checkbox = safeGetElement(`show-inactive-${type}`);
    return checkbox ? checkbox.checked : false;
}

// Enhanced fetch with timeout and better error handling
function fetchWithTimeout(
    url,
    options = {},
    timeout = window.MCPGATEWAY_UI_TOOL_TEST_TIMEOUT || 60000,
) {
    // Use configurable timeout from window.MCPGATEWAY_UI_TOOL_TEST_TIMEOUT
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
        console.warn(`Request to ${url} timed out after ${timeout}ms`);
        controller.abort();
    }, timeout);

    return fetch(url, {
        ...options,
        signal: controller.signal,
        // Add cache busting to prevent stale responses
        headers: {
            ...options.headers,
            "Cache-Control": "no-cache",
            Pragma: "no-cache",
        },
    })
        .then((response) => {
            clearTimeout(timeoutId);

            // FIX: Better handling of empty responses
            if (response.status === 0) {
                // Status 0 often indicates a network error or CORS issue
                throw new Error(
                    "Network error or server is not responding. Please ensure the server is running and accessible.",
                );
            }

            if (response.ok && response.status === 200) {
                const contentLength = response.headers.get("content-length");

                // Check Content-Length if present
                if (
                    contentLength !== null &&
                    parseInt(contentLength, 10) === 0
                ) {
                    console.warn(
                        `Empty response from ${url} (Content-Length: 0)`,
                    );
                    // Don't throw error for intentionally empty responses
                    return response;
                }

                // For responses without Content-Length, clone and check
                const cloned = response.clone();
                return cloned.text().then((text) => {
                    if (!text || !text.trim()) {
                        console.warn(`Empty response body from ${url}`);
                        // Return the original response anyway
                    }
                    return response;
                });
            }

            return response;
        })
        .catch((error) => {
            clearTimeout(timeoutId);

            // Improve error messages for common issues
            if (error.name === "AbortError") {
                throw new Error(
                    `Request timed out after ${timeout / 1000} seconds. The server may be slow or unresponsive.`,
                );
            } else if (
                error.message.includes("Failed to fetch") ||
                error.message.includes("NetworkError")
            ) {
                throw new Error(
                    "Unable to connect to server. Please check if the server is running on the correct port.",
                );
            } else if (
                error.message.includes("empty response") ||
                error.message.includes("ERR_EMPTY_RESPONSE")
            ) {
                throw new Error(
                    "Server returned an empty response. This endpoint may not be implemented yet or the server crashed.",
                );
            }

            throw error;
        });
}

// Safe element getter with logging
function safeGetElement(id, suppressWarning = false) {
    try {
        const element = document.getElementById(id);
        if (!element && !suppressWarning) {
            console.warn(`Element with id "${id}" not found`);
        }
        return element;
    } catch (error) {
        console.error(`Error getting element "${id}":`, error);
        return null;
    }
}

// Enhanced error handler for fetch operations
function handleFetchError(error, operation = "operation") {
    console.error(`Error during ${operation}:`, error);

    if (error.name === "AbortError") {
        return `Request timed out while trying to ${operation}. Please try again.`;
    } else if (error.message.includes("HTTP")) {
        return `Server error during ${operation}: ${error.message}`;
    } else if (
        error.message.includes("NetworkError") ||
        error.message.includes("Failed to fetch")
    ) {
        return `Network error during ${operation}. Please check your connection and try again.`;
    } else {
        return `Failed to ${operation}: ${error.message}`;
    }
}

// Show user-friendly error messages
function normalizePermissionErrorMessage(message) {
    const raw = String(message ?? "");
    const lower = raw.toLowerCase();
    const isPermissionError =
        lower.includes("403") ||
        lower.includes("forbidden") ||
        lower.includes("permission denied") ||
        lower.includes("insufficient permission") ||
        lower.includes("insufficient permissions") ||
        lower.includes("not enough permissions") ||
        lower.includes("access denied") ||
        lower.includes("not authorized") ||
        lower.includes("unauthorized");

    if (!isPermissionError) {
        return raw;
    }

    const requiredMatch = raw.match(/required:\s*([a-z0-9._:-]+)/i);
    const requiredPerm = requiredMatch?.[1] || "";

    if (!requiredPerm) {
        return "You don't have permission to perform this action.";
    }

    const [resourceRaw = "resource", actionRaw = "access"] = requiredPerm.split(".");
    const resource = resourceRaw.replace(/[_-]+/g, " ").trim();

    const actionMap = {
        create: "create",
        read: "view",
        view: "view",
        list: "view",
        discover: "discover",
        update: "edit",
        edit: "edit",
        write: "edit",
        delete: "delete",
        remove: "delete",
        test: "test",
        invoke: "test",
        execute: "test",
        manage: "manage",
        admin: "manage",
        toggle: "manage",
        activate: "manage",
        deactivate: "manage",
    };

    const action = actionMap[actionRaw] || "access";
    return `You don't have permission to ${action} ${resource}. Required: ${requiredPerm} (or admin access).`;
}

function showErrorMessage(message, elementId = null) {
    const normalizedMessage = normalizePermissionErrorMessage(message);
    console.error("Error:", normalizedMessage);

    if (elementId) {
        const element = safeGetElement(elementId);
        if (element) {
            element.textContent = normalizedMessage;
            element.classList.add("error-message", "text-red-600", "mt-2");
        }
    } else {
        // Show global error notification
        const errorDiv = document.createElement("div");
        errorDiv.className =
            "fixed top-4 right-4 bg-red-600 text-white px-4 py-2 rounded shadow-lg z-50";
        errorDiv.textContent = normalizedMessage;
        document.body.appendChild(errorDiv);

        setTimeout(() => {
            if (errorDiv.parentNode) {
                errorDiv.parentNode.removeChild(errorDiv);
            }
        }, 5000);
    }
}

// Show success messages
function showSuccessMessage(message, elementId = null) {
    console.log("Success:", message);

    // If an elementId is provided, render inline
    if (elementId) {
        const element = safeGetElement(elementId);
        if (element) {
            element.innerHTML = `
              <div class="text-green-700 dark:text-green-300 text-sm">
                ${escapeHtml(message)}
              </div>
            `;
            return;
        }
    }

    // Global toast fallback
    const successDiv = document.createElement("div");
    successDiv.className =
        "fixed top-4 right-4 bg-green-600 text-white px-4 py-2 rounded shadow-lg z-50";
    successDiv.textContent = message;
    document.body.appendChild(successDiv);

    setTimeout(() => {
        if (successDiv.parentNode) {
            successDiv.parentNode.removeChild(successDiv);
        }
    }, 3000);
}

// ===================================================================
// ENHANCED GLOBAL STATE MANAGEMENT
// ===================================================================

const AppState = {
    parameterCount: 0,
    currentTestTool: null,
    toolTestResultEditor: null,
    isInitialized: false,
    pendingRequests: new Set(),
    editors: {
        gateway: {
            headers: null,
            body: null,
            formHandler: null,
            closeHandler: null,
        },
    },

    // Track active modals to prevent multiple opens
    activeModals: new Set(),

    // Safe method to reset state
    reset() {
        this.parameterCount = 0;
        this.currentTestTool = null;
        this.toolTestResultEditor = null;
        this.activeModals.clear();

        // Cancel pending requests
        this.pendingRequests.forEach((controller) => {
            try {
                controller.abort();
            } catch (error) {
                console.warn("Error aborting request:", error);
            }
        });
        this.pendingRequests.clear();

        // Clean up editors
        Object.keys(this.editors.gateway).forEach((key) => {
            this.editors.gateway[key] = null;
        });

        // ADD THIS LINE: Clean up tool test state
        if (typeof cleanupToolTestState === "function") {
            cleanupToolTestState();
        }

        console.log("✓ Application state reset");
    },

    // Track requests for cleanup
    addPendingRequest(controller) {
        this.pendingRequests.add(controller);
    },

    removePendingRequest(controller) {
        this.pendingRequests.delete(controller);
    },

    // Safe parameter count management
    getParameterCount() {
        return this.parameterCount;
    },

    incrementParameterCount() {
        return ++this.parameterCount;
    },

    decrementParameterCount() {
        if (this.parameterCount > 0) {
            return --this.parameterCount;
        }
        return 0;
    },

    // Modal management
    isModalActive(modalId) {
        return this.activeModals.has(modalId);
    },

    setModalActive(modalId) {
        this.activeModals.add(modalId);
    },

    setModalInactive(modalId) {
        this.activeModals.delete(modalId);
    },
};

// Make state available globally but controlled
window.AppState = AppState;

// ===================================================================
// ENHANCED MODAL FUNCTIONS with Security and State Management
// ===================================================================

function openModal(modalId) {
    try {
        if (AppState.isModalActive(modalId)) {
            console.warn(`Modal ${modalId} is already active`);
            return;
        }

        const modal = safeGetElement(modalId);
        if (!modal) {
            console.error(`Modal ${modalId} not found`);
            return;
        }

        // Reset modal state
        const resetModelVariable = false;
        if (resetModelVariable) {
            resetModalState(modalId);
        }

        modal.classList.remove("hidden");
        AppState.setModalActive(modalId);

        console.log(`✓ Opened modal: ${modalId}`);
    } catch (error) {
        console.error(`Error opening modal ${modalId}:`, error);
    }
}

// Global event handler for Escape key
document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
        // Find any active modal
        const activeModal = Array.from(AppState.activeModals)[0];
        if (activeModal) {
            closeModal(activeModal);
        }
    }
});

function closeModal(modalId, clearId = null) {
    try {
        const modal = safeGetElement(modalId);
        if (!modal) {
            console.error(`Modal ${modalId} not found`);
            return;
        }

        // Clear specified content if provided
        if (clearId) {
            const resultEl = safeGetElement(clearId);
            if (resultEl) {
                resultEl.innerHTML = "";
            }
        }

        // Clean up specific modal types
        if (modalId === "gateway-test-modal") {
            cleanupGatewayTestModal();
        } else if (modalId === "tool-test-modal") {
            cleanupToolTestModal(); // ADD THIS LINE
        } else if (modalId === "prompt-test-modal") {
            cleanupPromptTestModal();
        }

        modal.classList.add("hidden");
        AppState.setModalInactive(modalId);

        console.log(`✓ Closed modal: ${modalId}`);
    } catch (error) {
        console.error(`Error closing modal ${modalId}:`, error);
    }
}

function resetModalState(modalId) {
    try {
        // Clear any dynamic content
        const modalContent = document.querySelector(
            `#${modalId} [data-dynamic-content]`,
        );
        if (modalContent) {
            modalContent.innerHTML = "";
        }

        // Reset any forms in the modal
        const forms = document.querySelectorAll(`#${modalId} form`);
        forms.forEach((form) => {
            try {
                form.reset();
                // Clear any error messages
                const errorElements = form.querySelectorAll(".error-message");
                errorElements.forEach((el) => el.remove());
            } catch (error) {
                console.error("Error resetting form:", error);
            }
        });

        console.log(`✓ Reset modal state: ${modalId}`);
    } catch (error) {
        console.error(`Error resetting modal state ${modalId}:`, error);
    }
}

// ===================================================================
// ENHANCED METRICS LOADING with Retry Logic and Request Deduplication
// ===================================================================

// More robust metrics request tracking
let metricsRequestController = null;
let metricsRequestPromise = null;
const MAX_METRICS_RETRIES = 3; // Increased from 2
const METRICS_RETRY_DELAY = 2000; // Increased from 1500ms

/**
 * Enhanced metrics loading with better race condition prevention
 */
async function loadAggregatedMetrics() {
    const metricsPanel = safeGetElement("metrics-panel", true);
    if (!metricsPanel || metricsPanel.closest(".tab-panel.hidden")) {
        console.log("Metrics panel not visible, skipping load");
        return;
    }

    // Cancel any existing request
    if (metricsRequestController) {
        console.log("Cancelling existing metrics request...");
        metricsRequestController.abort();
        metricsRequestController = null;
    }

    // If there's already a promise in progress, return it
    if (metricsRequestPromise) {
        console.log("Returning existing metrics promise...");
        return metricsRequestPromise;
    }

    console.log("Starting new metrics request...");
    showMetricsLoading();

    metricsRequestPromise = loadMetricsInternal().finally(() => {
        metricsRequestPromise = null;
        metricsRequestController = null;
        hideMetricsLoading();
    });

    return metricsRequestPromise;
}

async function loadMetricsInternal() {
    try {
        console.log("Loading aggregated metrics...");
        showMetricsLoading();

        const result = await fetchWithTimeoutAndRetry(
            `${window.ROOT_PATH}/admin/metrics`,
            {}, // options
            (window.MCPGATEWAY_UI_TOOL_TEST_TIMEOUT || 60000) * 1.5, // Use 1.5x configurable timeout for metrics
            MAX_METRICS_RETRIES,
        );

        if (!result.ok) {
            // If metrics endpoint doesn't exist, show a placeholder instead of failing
            if (result.status === 404) {
                showMetricsPlaceholder();
                return;
            }
            // FIX: Handle 500 errors specifically
            if (result.status >= 500) {
                throw new Error(
                    `Server error (${result.status}). The metrics calculation may have failed.`,
                );
            }
            throw new Error(`HTTP ${result.status}: ${result.statusText}`);
        }

        // FIX: Handle empty or invalid JSON responses
        let data;
        try {
            const text = await result.text();
            if (!text || !text.trim()) {
                console.warn("Empty metrics response, using default data");
                data = {}; // Use empty object as fallback
            } else {
                data = JSON.parse(text);
            }
        } catch (parseError) {
            console.error("Failed to parse metrics JSON:", parseError);
            data = {}; // Use empty object as fallback
        }

        displayMetrics(data);
        console.log("✓ Metrics loaded successfully");
    } catch (error) {
        console.error("Error loading aggregated metrics:", error);
        showMetricsError(error);
    } finally {
        hideMetricsLoading();
    }
}

/**
 * Enhanced fetch with automatic retry logic and better error handling
 */
async function fetchWithTimeoutAndRetry(
    url,
    options = {},
    timeout = window.MCPGATEWAY_UI_TOOL_TEST_TIMEOUT || 60000,
    maxRetries = 3,
) {
    let lastError;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            console.log(`Metrics fetch attempt ${attempt}/${maxRetries}`);

            // Create new controller for each attempt
            metricsRequestController = new AbortController();

            const response = await fetchWithTimeout(
                url,
                {
                    ...options,
                    signal: metricsRequestController.signal,
                },
                timeout,
            );

            console.log(`✓ Metrics fetch attempt ${attempt} succeeded`);
            return response;
        } catch (error) {
            lastError = error;

            console.warn(
                `✗ Metrics fetch attempt ${attempt} failed:`,
                error.message,
            );

            // Don't retry on certain errors
            if (error.name === "AbortError" && attempt < maxRetries) {
                console.log("Request was aborted, skipping retry");
                throw error;
            }

            // Don't retry on the last attempt
            if (attempt === maxRetries) {
                console.error(
                    `All ${maxRetries} metrics fetch attempts failed`,
                );
                throw error;
            }

            // Wait before retrying, with modest backoff
            const delay = METRICS_RETRY_DELAY * attempt;
            console.log(`Retrying metrics fetch in ${delay}ms...`);
            await new Promise((resolve) => setTimeout(resolve, delay));
        }
    }

    throw lastError;
}

/**
 * Show loading state for metrics
 */
function createMetricsHeaderCard() {
    const headerCard = document.createElement("div");
    headerCard.className = "metrics-header-card p-6 sm:p-8";
    headerCard.innerHTML = `
        <div class="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
            <div>
                <h2 class="metrics-title text-2xl font-bold">Gateway Metrics</h2>
                <p class="metrics-subtitle mt-1 text-sm">
                    Track tool, gateway, and server usage to spot failures and optimize performance.
                </p>
            </div>
            <button
                onclick="loadAggregatedMetrics()"
                class="metrics-primary-btn inline-flex items-center justify-center px-4 py-2 text-sm font-semibold"
            >
                Refresh Metrics
            </button>
        </div>
    `;
    return headerCard;
}

function createMetricsMainContainer() {
    const mainContainer = document.createElement("div");
    mainContainer.className = "space-y-6";
    mainContainer.appendChild(createMetricsHeaderCard());
    return mainContainer;
}

function showMetricsLoading() {
    const metricsPanel = safeGetElement("metrics-panel", true); // suppress warning
    if (metricsPanel) {
        const existingLoading = safeGetElement("metrics-loading", true);
        if (existingLoading) {
            return;
        }

        const mainContainer = createMetricsMainContainer();
        const loadingDiv = document.createElement("div");
        loadingDiv.id = "metrics-loading";
        loadingDiv.className =
            "metrics-surface-card p-8 flex justify-center items-center";
        loadingDiv.innerHTML = `
            <div class="text-center">
                <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
                <p class="text-gray-700 dark:text-gray-200 font-medium">Loading metrics...</p>
                <p class="text-sm text-gray-500 dark:text-gray-400 mt-2">This may take a moment</p>
            </div>
        `;
        metricsPanel.innerHTML = "";
        mainContainer.appendChild(loadingDiv);
        metricsPanel.appendChild(mainContainer);
    }
}

/**
 * Hide loading state for metrics
 */
function hideMetricsLoading() {
    const loadingDiv = safeGetElement("metrics-loading", true);
    if (loadingDiv && loadingDiv.parentNode) {
        loadingDiv.parentNode.removeChild(loadingDiv);
    }
}

/**
 * Enhanced error display with retry option
 */
function showMetricsError(error) {
    const metricsPanel = safeGetElement("metrics-panel");
    if (metricsPanel) {
        const mainContainer = createMetricsMainContainer();
        const errorDiv = document.createElement("div");
        errorDiv.className = "metrics-surface-card text-center p-8";

        const errorMessage = handleFetchError(error, "load metrics");

        // Determine if this looks like a server/network issue
        const isNetworkError =
            error.message.includes("fetch") ||
            error.message.includes("network") ||
            error.message.includes("timeout") ||
            error.name === "AbortError";

        const helpText = isNetworkError
            ? "This usually happens when the server is slow to respond or there's a network issue."
            : "There may be an issue with the metrics calculation on the server.";

        errorDiv.innerHTML = `
            <div class="text-red-600 mb-4">
                <svg class="w-12 h-12 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <h3 class="text-lg font-semibold mb-2">Failed to Load Metrics</h3>
                <p class="text-sm mb-2 text-gray-700 dark:text-gray-200">${escapeHtml(errorMessage)}</p>
                <p class="text-xs text-gray-500 dark:text-gray-400 mb-4">${helpText}</p>
                <button
                    onclick="retryLoadMetrics()"
                    class="metrics-primary-btn px-4 py-2 text-sm font-semibold">
                    Try Again
                </button>
            </div>
        `;

        metricsPanel.innerHTML = "";
        mainContainer.appendChild(errorDiv);
        metricsPanel.appendChild(mainContainer);
    }
}

/**
 * Retry loading metrics (callable from retry button)
 */
function retryLoadMetrics() {
    console.log("Manual retry requested");
    // Reset all tracking variables
    metricsRequestController = null;
    metricsRequestPromise = null;
    loadAggregatedMetrics();
}

// Make retry function available globally immediately
window.retryLoadMetrics = retryLoadMetrics;

function showMetricsPlaceholder() {
    const metricsPanel = safeGetElement("metrics-panel");
    if (metricsPanel) {
        const mainContainer = createMetricsMainContainer();
        const placeholderDiv = document.createElement("div");
        placeholderDiv.className = "metrics-surface-card text-center p-8";
        placeholderDiv.innerHTML = `
            <p class="text-gray-700 dark:text-gray-200 font-medium">
                Metrics endpoint not available.
            </p>
            <p class="text-sm text-gray-500 dark:text-gray-400 mt-2">
                This feature may not be implemented yet in this environment.
            </p>
        `;
        metricsPanel.innerHTML = "";
        mainContainer.appendChild(placeholderDiv);
        metricsPanel.appendChild(mainContainer);
    }
}

// ===================================================================
// ENHANCED METRICS DISPLAY with Complete System Overview
// ===================================================================

function displayMetrics(data) {
    const metricsPanel = safeGetElement("metrics-panel");
    if (!metricsPanel) {
        console.error("Metrics panel element not found");
        return;
    }

    try {
        // FIX: Handle completely empty data
        if (!data || Object.keys(data).length === 0) {
            const mainContainer = createMetricsMainContainer();
            const emptyStateDiv = document.createElement("div");
            emptyStateDiv.className =
                "metrics-surface-card text-center p-8 text-gray-500";
            emptyStateDiv.innerHTML = `
                <svg class="mx-auto h-12 w-12 text-gray-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path>
                </svg>
                <h3 class="text-lg font-semibold mb-2 text-gray-700 dark:text-gray-200">No Metrics Available</h3>
                <p class="text-sm text-gray-500 dark:text-gray-400">Metrics data will appear here once tools or gateways are executed.</p>
                <button onclick="retryLoadMetrics()" class="metrics-primary-btn mt-4 px-4 py-2 text-sm font-semibold">
                    Refresh Metrics
                </button>
            `;
            metricsPanel.innerHTML = "";
            mainContainer.appendChild(emptyStateDiv);
            metricsPanel.appendChild(mainContainer);
            return;
        }

        // Create main container with safe structure
        const mainContainer = createMetricsMainContainer();

        // System overview section (top priority display)
        if (data.system || data.overall) {
            const systemData = data.system || data.overall || {};
            const systemSummary = createSystemSummaryCard(systemData);
            mainContainer.appendChild(systemSummary);
        }

        // Key Performance Indicators section
        const kpiData = extractKPIData(data);
        if (Object.keys(kpiData).length > 0) {
            const kpiSection = createKPISection(kpiData);
            mainContainer.appendChild(kpiSection);
        }

        // Top Performers section (before individual metrics)
        if (data.topPerformers || data.top) {
            const topData = data.topPerformers || data.top;
            // const topSection = createTopPerformersSection(topData);
            const topSection = createEnhancedTopPerformersSection(topData);

            mainContainer.appendChild(topSection);
        }

        // Individual metrics grid for all components
        const metricsContainer = document.createElement("div");
        metricsContainer.className =
            "grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6";

        // Tools metrics
        if (data.tools) {
            const toolsCard = createMetricsCard("Tools", data.tools);
            metricsContainer.appendChild(toolsCard);
        }

        // Resources metrics
        // if (data.resources) {
        //     const resourcesCard = createMetricsCard(
        //         "Resources",
        //         data.resources,
        //     );
        //     metricsContainer.appendChild(resourcesCard);
        // }

        // Prompts metrics
        // if (data.prompts) {
        //     const promptsCard = createMetricsCard("Prompts", data.prompts);
        //     metricsContainer.appendChild(promptsCard);
        // }

        // Gateways metrics
        if (data.gateways) {
            const gatewaysCard = createMetricsCard("Gateways", data.gateways);
            metricsContainer.appendChild(gatewaysCard);
        }

        // Performance metrics
        if (data.performance) {
            const performanceCard = createPerformanceCard(data.performance);
            metricsContainer.appendChild(performanceCard);
        }

        mainContainer.appendChild(metricsContainer);

        // Recent activity section (bottom)
        if (data.recentActivity || data.recent) {
            const activityData = data.recentActivity || data.recent;
            const activitySection = createRecentActivitySection(activityData);
            mainContainer.appendChild(activitySection);
        }

        // Safe content replacement
        metricsPanel.innerHTML = "";
        metricsPanel.appendChild(mainContainer);

        console.log("✓ Enhanced metrics display rendered successfully");
    } catch (error) {
        console.error("Error displaying metrics:", error);
        showMetricsError(error);
    }
}

/**
 * SECURITY: Create system summary card with safe HTML generation
 */
function createSystemSummaryCard(systemData) {
    try {
        const card = document.createElement("div");
        card.className = "metrics-system-card p-6 sm:p-7";

        // Card title
        const title = document.createElement("h2");
        title.className = "text-2xl font-bold mb-5";
        title.textContent = "System Overview";
        card.appendChild(title);

        // Statistics grid
        const statsGrid = document.createElement("div");
        statsGrid.className = "grid grid-cols-2 md:grid-cols-4 gap-4";

        // Define system statistics with validation
        const systemStats = [
            {
                key: "uptime",
                label: "Uptime",
                suffix: "",
            },
            {
                key: "totalRequests",
                label: "Total Requests",
                suffix: "",
            },
            {
                key: "activeConnections",
                label: "Active Connections",
                suffix: "",
            },
            {
                key: "memoryUsage",
                label: "Memory Usage",
                suffix: "%",
            },
            {
                key: "cpuUsage",
                label: "CPU Usage",
                suffix: "%",
            },
            {
                key: "diskUsage",
                label: "Disk Usage",
                suffix: "%",
            },
            {
                key: "networkIn",
                label: "Network In",
                suffix: " MB",
            },
            {
                key: "networkOut",
                label: "Network Out",
                suffix: " MB",
            },
        ];

        systemStats.forEach((stat) => {
            const value =
                systemData[stat.key] ??
                systemData[stat.key.replace(/([A-Z])/g, "_$1").toLowerCase()] ??
                "N/A";

            const statDiv = document.createElement("div");
            statDiv.className =
                "rounded-lg bg-white/10 border border-white/15 p-3 text-center";

            const valueSpan = document.createElement("div");
            valueSpan.className = "text-2xl font-bold";
            valueSpan.textContent =
                (value === "N/A" ? "N/A" : String(value)) + stat.suffix;

            const labelSpan = document.createElement("div");
            labelSpan.className = "text-blue-100 text-xs uppercase tracking-wide";
            labelSpan.textContent = stat.label;

            statDiv.appendChild(valueSpan);
            statDiv.appendChild(labelSpan);
            statsGrid.appendChild(statDiv);
        });

        card.appendChild(statsGrid);
        return card;
    } catch (error) {
        console.error("Error creating system summary card:", error);
        return document.createElement("div"); // Safe fallback
    }
}

/**
 * SECURITY: Create KPI section with safe data handling
 */
function createKPISection(kpiData) {
    try {
        const section = document.createElement("div");
        section.className = "grid grid-cols-1 md:grid-cols-4 gap-4";

        // Define KPI indicators with safe configuration
        const kpis = [
            {
                key: "totalExecutions",
                label: "Total Executions",
                colorClass: "metrics-kpi-blue",
            },
            {
                key: "successRate",
                label: "Success Rate",
                colorClass: "metrics-kpi-green",
                suffix: "%",
            },
            {
                key: "avgResponseTime",
                label: "Avg Response Time",
                colorClass: "metrics-kpi-amber",
                suffix: "ms",
            },
            {
                key: "errorRate",
                label: "Error Rate",
                colorClass: "metrics-kpi-red",
                suffix: "%",
            },
        ];

        kpis.forEach((kpi) => {
            const value = kpiData[kpi.key] ?? "N/A";

            const kpiCard = document.createElement("div");
            kpiCard.className = `metrics-kpi-card ${kpi.colorClass} p-4`;

            const header = document.createElement("div");
            header.className = "flex items-stretch gap-3";

            const accent = document.createElement("span");
            accent.className = "metrics-kpi-accent";
            header.appendChild(accent);

            const valueDiv = document.createElement("div");
            valueDiv.className = "flex-1";

            const valueSpan = document.createElement("div");
            valueSpan.className = "text-2xl font-bold text-gray-900 dark:text-gray-100";
            valueSpan.textContent =
                (value === "N/A" ? "N/A" : String(value)) + (kpi.suffix || "");

            const labelSpan = document.createElement("div");
            labelSpan.className =
                "text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400";
            labelSpan.textContent = kpi.label;

            valueDiv.appendChild(valueSpan);
            valueDiv.appendChild(labelSpan);
            header.appendChild(valueDiv);
            kpiCard.appendChild(header);
            section.appendChild(kpiCard);
        });

        return section;
    } catch (error) {
        console.error("Error creating KPI section:", error);
        return document.createElement("div"); // Safe fallback
    }
}

/**
 * SECURITY: Extract and calculate KPI data with validation
 */
function extractKPIData(data) {
    try {
        const kpiData = {};

        // Initialize calculation variables
        let totalExecutions = 0;
        let totalSuccessful = 0;
        let totalFailed = 0;
        const responseTimes = [];

        // Process each category safely
        const categories = [
            "tools",
            "resources",
            "prompts",
            "gateways",
        ];
        categories.forEach((category) => {
            if (data[category]) {
                const categoryData = data[category];
                totalExecutions += Number(categoryData.totalExecutions || 0);
                totalSuccessful += Number(
                    categoryData.successfulExecutions || 0,
                );
                totalFailed += Number(categoryData.failedExecutions || 0);

                if (
                    categoryData.avgResponseTime &&
                    categoryData.avgResponseTime !== "N/A"
                ) {
                    responseTimes.push(Number(categoryData.avgResponseTime));
                }
            }
        });

        // Calculate safe aggregate metrics
        kpiData.totalExecutions = totalExecutions;
        kpiData.successRate =
            totalExecutions > 0
                ? Math.round((totalSuccessful / totalExecutions) * 100)
                : 0;
        kpiData.errorRate =
            totalExecutions > 0
                ? Math.round((totalFailed / totalExecutions) * 100)
                : 0;
        kpiData.avgResponseTime =
            responseTimes.length > 0
                ? Math.round(
                      responseTimes.reduce((a, b) => a + b, 0) /
                          responseTimes.length,
                  )
                : "N/A";

        return kpiData;
    } catch (error) {
        console.error("Error extracting KPI data:", error);
        return {}; // Safe fallback
    }
}

/**
 * SECURITY: Create top performers section with safe display
 */
// function createTopPerformersSection(topData) {
//     try {
//         const section = document.createElement("div");
//         section.className = "bg-white rounded-lg shadow p-6 dark:bg-gray-800";

//         const title = document.createElement("h3");
//         title.className = "text-lg font-medium mb-4 dark:text-gray-200";
//         title.textContent = "Top Performers";
//         section.appendChild(title);

//         const grid = document.createElement("div");
//         grid.className = "grid grid-cols-1 md:grid-cols-2 gap-4";

//         // Top Tools
//         if (topData.tools && Array.isArray(topData.tools)) {
//             const toolsCard = createTopItemCard("Tools", topData.tools);
//             grid.appendChild(toolsCard);
//         }

//         // Top Resources
//         if (topData.resources && Array.isArray(topData.resources)) {
//             const resourcesCard = createTopItemCard(
//                 "Resources",
//                 topData.resources,
//             );
//             grid.appendChild(resourcesCard);
//         }

//         // Top Prompts
//         if (topData.prompts && Array.isArray(topData.prompts)) {
//             const promptsCard = createTopItemCard("Prompts", topData.prompts);
//             grid.appendChild(promptsCard);
//         }

//         // Top Servers
//         if (topData.servers && Array.isArray(topData.servers)) {
//             const serversCard = createTopItemCard("Servers", topData.servers);
//             grid.appendChild(serversCard);
//         }

//         section.appendChild(grid);
//         return section;
//     } catch (error) {
//         console.error("Error creating top performers section:", error);
//         return document.createElement("div"); // Safe fallback
//     }
// }
function createEnhancedTopPerformersSection(topData) {
    try {
        const section = document.createElement("div");
        section.className = "metrics-surface-card p-6";

        const title = document.createElement("h3");
        title.className = "text-lg font-semibold mb-4 text-gray-800 dark:text-gray-100";
        title.textContent = "Top Performers";
        title.setAttribute("aria-label", "Top Performers Section");
        section.appendChild(title);

        // Tabs
        const tabsContainer = document.createElement("div");
        tabsContainer.className = "border-b border-gray-200 dark:border-gray-700";
        const tabList = document.createElement("nav");
        tabList.className = "-mb-px flex space-x-6 overflow-x-auto";
        tabList.setAttribute("aria-label", "Top Performers Tabs");

        const entityTypes = [
            "tools",
            // "resources",
            // "prompts",
            "gateways",
        ];
        entityTypes.forEach((type, index) => {
            if (topData[type] && Array.isArray(topData[type])) {
                const tab = createTab(type, index === 0);
                tabList.appendChild(tab);
            }
        });

        tabsContainer.appendChild(tabList);
        section.appendChild(tabsContainer);

        // Content panels
        const contentContainer = document.createElement("div");
        contentContainer.className = "mt-4";

        entityTypes.forEach((type, index) => {
            if (topData[type] && Array.isArray(topData[type])) {
                const panel = createTopPerformersTable(
                    type,
                    topData[type],
                    index === 0,
                );
                contentContainer.appendChild(panel);
            }
        });

        section.appendChild(contentContainer);

        // Export button
        const exportButton = document.createElement("button");
        exportButton.className =
            "metrics-primary-btn mt-4 px-4 py-2 text-sm font-semibold";
        exportButton.textContent = "Export Metrics";
        exportButton.onclick = () => exportMetricsToCSV(topData);
        section.appendChild(exportButton);

        return section;
    } catch (error) {
        console.error("Error creating enhanced top performers section:", error);
        showErrorMessage("Failed to load top performers section");
        return document.createElement("div");
    }
}
function calculateSuccessRate(item) {
    // API returns successRate directly as a percentage
    if (item.successRate !== undefined && item.successRate !== null) {
        return Math.round(item.successRate);
    }
    // Fallback for legacy format (if needed)
    const total =
        item.execution_count || item.executions || item.executionCount || 0;
    const successful = item.successful_count || item.successfulExecutions || 0;
    return total > 0 ? Math.round((successful / total) * 100) : 0;
}

function formatNumber(num) {
    return new Intl.NumberFormat().format(num);
}

function formatLastUsed(timestamp) {
    if (!timestamp) {
        return "Never";
    }

    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) {
        return "Just now";
    }
    if (diffMins < 60) {
        return `${diffMins} min ago`;
    }
    if (diffMins < 1440) {
        return `${Math.floor(diffMins / 60)} hours ago`;
    }
    if (diffMins < 10080) {
        return `${Math.floor(diffMins / 1440)} days ago`;
    }

    return date.toLocaleDateString();
}
function createTopPerformersTable(entityType, data, isActive) {
    const panel = document.createElement("div");
    panel.id = `top-${entityType}-panel`;
    panel.className = `transition-opacity duration-300 ${isActive ? "opacity-100" : "hidden opacity-0"}`;
    panel.setAttribute("role", "tabpanel");
    panel.setAttribute("aria-labelledby", `top-${entityType}-tab`);

    if (data.length === 0) {
        const emptyState = document.createElement("p");
        emptyState.className =
            "text-gray-500 dark:text-gray-400 text-center py-4";
        emptyState.textContent = `No ${entityType} data available`;
        panel.appendChild(emptyState);
        return panel;
    }

    // Responsive table wrapper
    const tableWrapper = document.createElement("div");
    tableWrapper.className = "metrics-table-wrap";

    const table = document.createElement("table");
    table.className = "metrics-table min-w-full divide-y divide-gray-200 dark:divide-gray-700";

    // Table header
    const thead = document.createElement("thead");
    thead.className = "hidden sm:table-header-group";
    const headerRow = document.createElement("tr");
    const headers = [
        "Rank",
        "Name",
        "Executions",
        "Avg Response Time",
        "Success Rate",
        "Last Used",
    ];

    headers.forEach((headerText, index) => {
        const th = document.createElement("th");
        th.className =
            "px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-300 uppercase tracking-wider";
        th.setAttribute("scope", "col");
        th.textContent = headerText;
        if (index === 0) {
            th.setAttribute("aria-sort", "ascending");
        }
        headerRow.appendChild(th);
    });

    thead.appendChild(headerRow);
    table.appendChild(thead);

    // Table body
    const tbody = document.createElement("tbody");
    tbody.className =
        "bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700";

    // Pagination (if > 5 items)
    const paginatedData = data.slice(0, 5); // Limit to top 5
    paginatedData.forEach((item, index) => {
        const row = document.createElement("tr");
        row.className =
            "hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors duration-200";

        // Rank
        const rankCell = document.createElement("td");
        rankCell.className =
            "px-4 py-3 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-gray-100";
        const rankBadge = document.createElement("span");
        rankBadge.className = `inline-flex items-center justify-center w-6 h-6 rounded-full ${
            index === 0
                ? "bg-yellow-400 text-yellow-900"
                : index === 1
                  ? "bg-gray-300 text-gray-900"
                  : index === 2
                    ? "bg-orange-400 text-orange-900"
                    : "bg-gray-100 text-gray-600"
        }`;
        rankBadge.textContent = index + 1;
        rankBadge.setAttribute("aria-label", `Rank ${index + 1}`);
        rankCell.appendChild(rankBadge);
        row.appendChild(rankCell);

        // Name (clickable for drill-down)
        const nameCell = document.createElement("td");
        nameCell.className =
            "px-4 py-3 whitespace-nowrap text-sm font-medium text-blue-700 dark:text-blue-300 cursor-pointer";
        nameCell.textContent = escapeHtml(item.name || "Unknown");
        // nameCell.onclick = () => showDetailedMetrics(entityType, item.id);
        nameCell.setAttribute("role", "button");
        nameCell.setAttribute(
            "aria-label",
            `View details for ${item.name || "Unknown"}`,
        );
        row.appendChild(nameCell);

        // Executions
        const execCell = document.createElement("td");
        execCell.className =
            "px-4 py-3 whitespace-nowrap text-sm text-gray-600 dark:text-gray-300";
        execCell.textContent = formatNumber(
            item.executionCount || item.execution_count || item.executions || 0,
        );
        row.appendChild(execCell);

        // Avg Response Time
        const avgTimeCell = document.createElement("td");
        avgTimeCell.className =
            "px-4 py-3 whitespace-nowrap text-sm text-gray-600 dark:text-gray-300";
        const avgTime = item.avg_response_time || item.avgResponseTime;
        avgTimeCell.textContent = avgTime ? `${Math.round(avgTime)}ms` : "N/A";
        row.appendChild(avgTimeCell);

        // Success Rate
        const successCell = document.createElement("td");
        successCell.className =
            "px-4 py-3 whitespace-nowrap text-sm";
        const successRate = calculateSuccessRate(item);
        const successBadge = document.createElement("span");
        successBadge.className = `inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
            successRate >= 95
                ? "bg-green-100 text-green-800 dark:bg-green-800 dark:text-green-100"
                : successRate >= 80
                  ? "bg-yellow-100 text-yellow-800 dark:bg-yellow-800 dark:text-yellow-100"
                  : "bg-red-100 text-red-800 dark:bg-red-800 dark:text-red-100"
        }`;
        successBadge.textContent = `${successRate}%`;
        successBadge.setAttribute(
            "aria-label",
            `Success rate: ${successRate}%`,
        );
        successCell.appendChild(successBadge);
        row.appendChild(successCell);

        // Last Used
        const lastUsedCell = document.createElement("td");
        lastUsedCell.className =
            "px-4 py-3 whitespace-nowrap text-sm text-gray-600 dark:text-gray-300";
        lastUsedCell.textContent = formatLastUsed(
            item.last_execution || item.lastExecution,
        );
        row.appendChild(lastUsedCell);

        tbody.appendChild(row);
    });

    table.appendChild(tbody);
    tableWrapper.appendChild(table);
    panel.appendChild(tableWrapper);

    // Pagination controls (if needed)
    if (data.length > 5) {
        const pagination = createPaginationControls(data.length, 5, (page) => {
            updateTableRows(panel, entityType, data, page);
        });
        panel.appendChild(pagination);
    }

    return panel;
}

function createTab(type, isActive) {
    const tab = document.createElement("a");
    tab.href = "#";
    tab.id = `top-${type}-tab`;
    tab.className = `metrics-tab ${isActive ? "active" : ""}`;
    tab.textContent = type;
    tab.setAttribute("role", "tab");
    tab.setAttribute("aria-controls", `top-${type}-panel`);
    tab.setAttribute("aria-selected", isActive.toString());
    tab.onclick = (e) => {
        e.preventDefault();
        showTopPerformerTab(type);
    };
    return tab;
}

function showTopPerformerTab(activeType) {
    const entityTypes = [
        "tools",
        // "resources",
        // "prompts",
        "gateways",
    ];
    entityTypes.forEach((type) => {
        const panel = document.getElementById(`top-${type}-panel`);
        const tab = document.getElementById(`top-${type}-tab`);
        if (panel) {
            panel.classList.toggle("hidden", type !== activeType);
            panel.classList.toggle("opacity-100", type === activeType);
            panel.classList.toggle("opacity-0", type !== activeType);
            panel.setAttribute("aria-hidden", type !== activeType);
        }
        if (tab) {
            tab.classList.toggle("active", type === activeType);
            tab.setAttribute("aria-selected", type === activeType);
        }
    });
}

function createPaginationControls(totalItems, itemsPerPage, onPageChange) {
    const pagination = document.createElement("div");
    pagination.className = "mt-4 flex justify-end space-x-2";
    const totalPages = Math.ceil(totalItems / itemsPerPage);

    for (let page = 1; page <= totalPages; page++) {
        const button = document.createElement("button");
        button.className = `px-3 py-1.5 text-sm font-medium rounded-lg ${page === 1 ? "metrics-primary-btn text-white" : "metrics-secondary-btn"}`;
        button.textContent = page;
        button.onclick = () => {
            onPageChange(page);
            pagination.querySelectorAll("button").forEach((btn) => {
                btn.className = `px-3 py-1.5 text-sm font-medium rounded-lg ${btn === button ? "metrics-primary-btn text-white" : "metrics-secondary-btn"}`;
            });
        };
        pagination.appendChild(button);
    }

    return pagination;
}

function updateTableRows(panel, entityType, data, page) {
    const tbody = panel.querySelector("tbody");
    tbody.innerHTML = "";
    const start = (page - 1) * 5;
    const paginatedData = data.slice(start, start + 5);

    paginatedData.forEach((item, index) => {
        const row = document.createElement("tr");
        // ... (same row creation logic as in createTopPerformersTable)
        tbody.appendChild(row);
    });
}

function exportMetricsToCSV(topData) {
    const headers = [
        "Entity Type",
        "Rank",
        "Name",
        "Executions",
        "Avg Response Time",
        "Success Rate",
        "Last Used",
    ];
    const rows = [];

    ["tools", /*"resources", "prompts",*/ "gateways"].forEach((type) => {
        if (topData[type] && Array.isArray(topData[type])) {
            topData[type].forEach((item, index) => {
                rows.push([
                    type,
                    index + 1,
                    `"${escapeHtml(item.name || "Unknown")}"`,
                    formatNumber(
                        item.executionCount ||
                            item.execution_count ||
                            item.executions ||
                            0,
                    ),
                    item.avg_response_time || item.avgResponseTime
                        ? `${Math.round(item.avg_response_time || item.avgResponseTime)}ms`
                        : "N/A",
                    `${calculateSuccessRate(item)}%`,
                    formatLastUsed(item.last_execution || item.lastExecution),
                ]);
            });
        }
    });

    const csv = [headers.join(","), ...rows.map((row) => row.join(","))].join(
        "\n",
    );
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `top_performers_${new Date().toISOString()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
}

/**
 * SECURITY: Create top item card with safe content handling
 */
// function createTopItemCard(title, items) {
//     try {
//         const card = document.createElement("div");
//         card.className = "bg-gray-50 rounded p-4 dark:bg-gray-700";

//         const cardTitle = document.createElement("h4");
//         cardTitle.className = "font-medium mb-2 dark:text-gray-200";
//         cardTitle.textContent = `Top ${title}`;
//         card.appendChild(cardTitle);

//         const list = document.createElement("ul");
//         list.className = "space-y-1";

//         items.slice(0, 5).forEach((item) => {
//             const listItem = document.createElement("li");
//             listItem.className =
//                 "text-sm text-gray-600 dark:text-gray-300 flex justify-between";

//             const nameSpan = document.createElement("span");
//             nameSpan.textContent = item.name || "Unknown";

//             const countSpan = document.createElement("span");
//             countSpan.className = "font-medium";
//             countSpan.textContent = String(item.executions || 0);

//             listItem.appendChild(nameSpan);
//             listItem.appendChild(countSpan);
//             list.appendChild(listItem);
//         });

//         card.appendChild(list);
//         return card;
//     } catch (error) {
//         console.error("Error creating top item card:", error);
//         return document.createElement("div"); // Safe fallback
//     }
// }

/**
 * SECURITY: Create performance metrics card with safe display
 */
function createPerformanceCard(performanceData) {
    try {
        const card = document.createElement("div");
        card.className = "metrics-surface-card p-6";

        const titleElement = document.createElement("h3");
        titleElement.className = "text-lg font-semibold mb-4 text-gray-800 dark:text-gray-100";
        titleElement.textContent = "Performance Metrics";
        card.appendChild(titleElement);

        const metricsList = document.createElement("div");
        metricsList.className = "space-y-2";

        // Define performance metrics with safe structure
        const performanceMetrics = [
            { key: "memoryUsage", label: "Memory Usage" },
            { key: "cpuUsage", label: "CPU Usage" },
            { key: "diskIo", label: "Disk I/O" },
            { key: "networkThroughput", label: "Network Throughput" },
            { key: "cacheHitRate", label: "Cache Hit Rate" },
            { key: "activeThreads", label: "Active Threads" },
        ];

        performanceMetrics.forEach((metric) => {
            const value =
                performanceData[metric.key] ??
                performanceData[
                    metric.key.replace(/([A-Z])/g, "_$1").toLowerCase()
                ] ??
                "N/A";

            const metricRow = document.createElement("div");
            metricRow.className =
                "flex justify-between rounded-lg px-3 py-2 bg-gray-50 dark:bg-gray-900/50";

            const label = document.createElement("span");
            label.className = "text-gray-600 dark:text-gray-400";
            label.textContent = metric.label + ":";

            const valueSpan = document.createElement("span");
            valueSpan.className = "font-medium dark:text-gray-200";
            valueSpan.textContent = value === "N/A" ? "N/A" : String(value);

            metricRow.appendChild(label);
            metricRow.appendChild(valueSpan);
            metricsList.appendChild(metricRow);
        });

        card.appendChild(metricsList);
        return card;
    } catch (error) {
        console.error("Error creating performance card:", error);
        return document.createElement("div"); // Safe fallback
    }
}

/**
 * SECURITY: Create recent activity section with safe content handling
 */
function createRecentActivitySection(activityData) {
    try {
        const section = document.createElement("div");
        section.className = "metrics-surface-card p-6";

        const title = document.createElement("h3");
        title.className = "text-lg font-semibold mb-4 text-gray-800 dark:text-gray-100";
        title.textContent = "Recent Activity";
        section.appendChild(title);

        if (Array.isArray(activityData) && activityData.length > 0) {
            const activityList = document.createElement("div");
            activityList.className = "space-y-3 max-h-64 overflow-y-auto";

            // Display up to 10 recent activities safely
            activityData.slice(0, 10).forEach((activity) => {
                const activityItem = document.createElement("div");
                activityItem.className =
                    "flex items-center justify-between p-3 bg-gray-50 rounded-lg dark:bg-gray-900/50 border border-gray-100 dark:border-gray-700";

                const leftSide = document.createElement("div");

                const actionSpan = document.createElement("span");
                actionSpan.className = "font-medium dark:text-gray-200";
                actionSpan.textContent = escapeHtml(
                    activity.action || "Unknown Action",
                );

                const targetSpan = document.createElement("span");
                targetSpan.className =
                    "text-sm text-gray-500 dark:text-gray-400 ml-2";
                targetSpan.textContent = escapeHtml(activity.target || "");

                leftSide.appendChild(actionSpan);
                leftSide.appendChild(targetSpan);

                const rightSide = document.createElement("div");
                rightSide.className = "text-xs text-gray-400";
                rightSide.textContent = escapeHtml(activity.timestamp || "");

                activityItem.appendChild(leftSide);
                activityItem.appendChild(rightSide);
                activityList.appendChild(activityItem);
            });

            section.appendChild(activityList);
        } else {
            const noActivity = document.createElement("p");
            noActivity.className =
                "text-gray-500 dark:text-gray-400 text-center py-4";
            noActivity.textContent = "No recent activity to display";
            section.appendChild(noActivity);
        }

        return section;
    } catch (error) {
        console.error("Error creating recent activity section:", error);
        return document.createElement("div"); // Safe fallback
    }
}

function createMetricsCard(title, metrics) {
    const card = document.createElement("div");
    card.className = "metrics-surface-card p-6";

    const titleElement = document.createElement("h3");
    titleElement.className = "text-lg font-semibold mb-4 text-gray-800 dark:text-gray-100";
    titleElement.textContent = `${title} Metrics`;
    card.appendChild(titleElement);

    const metricsList = document.createElement("div");
    metricsList.className = "space-y-2";

    const metricsToShow = [
        { key: "totalExecutions", label: "Total Executions" },
        { key: "successfulExecutions", label: "Successful Executions" },
        { key: "failedExecutions", label: "Failed Executions" },
        { key: "failureRate", label: "Failure Rate" },
        { key: "avgResponseTime", label: "Average Response Time" },
        { key: "lastExecutionTime", label: "Last Execution Time" },
    ];

    metricsToShow.forEach((metric) => {
        const value =
            metrics[metric.key] ??
            metrics[metric.key.replace(/([A-Z])/g, "_$1").toLowerCase()] ??
            "N/A";

        const metricRow = document.createElement("div");
        metricRow.className =
            "flex justify-between rounded-lg px-3 py-2 bg-gray-50 dark:bg-gray-900/50";

        const label = document.createElement("span");
        label.className = "text-gray-600 dark:text-gray-400";
        label.textContent = metric.label + ":";

        const valueSpan = document.createElement("span");
        valueSpan.className = "font-medium dark:text-gray-200";
        valueSpan.textContent = value === "N/A" ? "N/A" : String(value);

        metricRow.appendChild(label);
        metricRow.appendChild(valueSpan);
        metricsList.appendChild(metricRow);
    });

    card.appendChild(metricsList);
    return card;
}

// ===================================================================
// SECURE CRUD OPERATIONS with Input Validation
// ===================================================================

/**
 * SECURE: Edit Tool function with input validation
 */
async function editTool(toolId) {
  try {
    console.log(`Editing tool ID: ${toolId}`);

    // ✅ CHANGED: use /tools/{id} (router-style), and read backend message
    const response = await fetchWithTimeout(`${window.ROOT_PATH}/tools/${toolId}`);
    const { data: tool, message } = await readBackendMessage(response);

    if (!response.ok) {
      throw new Error(message || `Failed to load tool (HTTP ${response.status})`);
    }

    const isInactiveCheckedBool = isInactiveChecked("tools");
    let hiddenField = safeGetElement("edit-show-inactive");
    if (!hiddenField) {
      hiddenField = document.createElement("input");
      hiddenField.type = "hidden";
      hiddenField.name = "is_inactive_checked";
      hiddenField.id = "edit-show-inactive";
      const editForm = safeGetElement("edit-tool-form");
      if (editForm) {
        editForm.appendChild(hiddenField);
      }
    }
    hiddenField.value = String(isInactiveCheckedBool);

    // ✅ CHANGED: set action to /tools/{id} so PUT interceptor can use it
    const editForm = safeGetElement("edit-tool-form");
    if (editForm) {
      editForm.action = `${window.ROOT_PATH}/tools/${toolId}`;
    }

    // Validate and set fields
    const nameValidation = validateInputName(tool.name, "tool");
    const customNameValidation = validateInputName(tool.customName, "tool");
    const urlValidation = validateUrl(tool.url);

    const nameField = safeGetElement("edit-tool-name");
    const customNameField = safeGetElement("edit-tool-custom-name");
    const urlField = safeGetElement("edit-tool-url");
    const descField = safeGetElement("edit-tool-description");
    const typeField = safeGetElement("edit-tool-type");

    if (nameField && nameValidation.valid) nameField.value = nameValidation.value;
    if (customNameField && customNameValidation.valid) customNameField.value = customNameValidation.value;

    const displayNameField = safeGetElement("edit-tool-display-name");
    if (displayNameField) displayNameField.value = tool.displayName || "";

    if (urlField && urlValidation.valid) urlField.value = urlValidation.value;
    if (descField) descField.value = tool.description || "";
    if (typeField) typeField.value = tool.integrationType || "MCP";

    // Tags
    const tagsField = safeGetElement("edit-tool-tags");
    if (tagsField) tagsField.value = tool.tags ? tool.tags.join(", ") : "";

    // ✅ CHANGED: avoid adding team_id hidden input repeatedly
    const teamId = new URL(window.location.href).searchParams.get("team_id");
    if (teamId && editForm && !editForm.querySelector('input[name="team_id"]')) {
      const hiddenInput = document.createElement("input");
      hiddenInput.type = "hidden";
      hiddenInput.name = "team_id";
      hiddenInput.value = teamId;
      editForm.appendChild(hiddenInput);
    }

    // Visibility radios
    const visibility = tool.visibility;
    const publicRadio = safeGetElement("edit-tool-visibility-public");
    const teamRadio = safeGetElement("edit-tool-visibility-team");
    const privateRadio = safeGetElement("edit-tool-visibility-private");

    if (visibility === "public" && publicRadio) publicRadio.checked = true;
    else if (visibility === "team" && teamRadio) teamRadio.checked = true;
    else if (visibility === "private" && privateRadio) privateRadio.checked = true;

    // JSON fields safely
    const headersValidation = validateJson(JSON.stringify(tool.headers || {}), "Headers");
    const schemaValidation = validateJson(JSON.stringify(tool.inputSchema || {}), "Schema");
    const annotationsValidation = validateJson(JSON.stringify(tool.annotations || {}), "Annotations");

    const headersField = safeGetElement("edit-tool-headers");
    const schemaField = safeGetElement("edit-tool-schema");
    const annotationsField = safeGetElement("edit-tool-annotations");

    if (headersField && headersValidation.valid) {
      headersField.value = JSON.stringify(headersValidation.value, null, 2);
    }
    if (schemaField && schemaValidation.valid) {
      schemaField.value = JSON.stringify(schemaValidation.value, null, 2);
    }
    if (annotationsField && annotationsValidation.valid) {
      annotationsField.value = JSON.stringify(annotationsValidation.value, null, 2);
    }

    // CodeMirror editors
    if (window.editToolHeadersEditor && headersValidation.valid) {
      window.editToolHeadersEditor.setValue(JSON.stringify(headersValidation.value, null, 2));
      window.editToolHeadersEditor.refresh();
    }
    if (window.editToolSchemaEditor && schemaValidation.valid) {
      window.editToolSchemaEditor.setValue(JSON.stringify(schemaValidation.value, null, 2));
      window.editToolSchemaEditor.refresh();
    }

    // Integration + request types
    if (typeField) {
      typeField.value = tool.integrationType || "REST";
      if (tool.integrationType === "MCP") typeField.disabled = true;
      else typeField.disabled = false;

      updateEditToolRequestTypes(tool.requestType || null);
      updateEditToolUrl(tool.url || null);
    }

    // Request Type field handling (disable for MCP)
    const requestTypeField = safeGetElement("edit-tool-request-type");
    if (requestTypeField) {
      if ((tool.integrationType || "REST") === "MCP") {
        requestTypeField.value = "";
        requestTypeField.disabled = true;
      } else {
        requestTypeField.disabled = false;
        requestTypeField.value = tool.requestType || "";
      }
    }

    // ✅ Keep your modal open behavior (same as servers)
    openModal("tool-edit-modal");

    console.log("✓ Tool edit modal loaded successfully");
  } catch (error) {
    console.error("Error fetching tool for editing:", error);
    showErrorMessage(error?.message || "Failed to load tool for editing");
  }
}

(function wireToolEditPut() {
  let wired = false;

  function getToolIdFromAction(actionUrl) {
    try {
      const u = new URL(actionUrl, window.location.origin);
      const parts = u.pathname.split("/").filter(Boolean);
      const idx = parts.indexOf("tools");
      if (idx >= 0 && parts[idx + 1]) return parts[idx + 1];
    } catch (_) {}
    return null;
  }

  function normalizeTags(tagsStr) {
    if (!tagsStr) return [];
    return tagsStr
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);
  }

  function safeParseJsonOrThrow(val, label) {
    const s = (val ?? "").toString().trim();
    if (!s) return {}; // empty allowed -> {}
    const v = validateJson(s, label);
    if (!v.valid) throw new Error(v.error || `Invalid JSON for ${label}`);
    return v.value;
  }

  function getVisibilityFromEditRadios() {
    const visPublic = safeGetElement("edit-tool-visibility-public")?.checked;
    const visTeam = safeGetElement("edit-tool-visibility-team")?.checked;
    const visPrivate = safeGetElement("edit-tool-visibility-private")?.checked;
    return visPublic ? "public" : visTeam ? "team" : visPrivate ? "private" : undefined;
  }

  async function handleEditToolSubmit(event) {
    event.preventDefault();
    event.stopPropagation();
    if (typeof event.stopImmediatePropagation === "function") {
      event.stopImmediatePropagation();
    }

    const form = event.target;
    const statusElId = "status-tools";

    const submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');
    if (submitBtn) {
      if (submitBtn.disabled) return;
      submitBtn.disabled = true;
    }

    try {
      const toolId = getToolIdFromAction(form.action || "");
      if (!toolId) throw new Error("Could not determine tool id from form action");

      // Read fields from edit modal
      const name = safeGetElement("edit-tool-name")?.value?.trim();
      const customName = safeGetElement("edit-tool-custom-name")?.value?.trim();
      const displayName = safeGetElement("edit-tool-display-name")?.value ?? "";
      const url = safeGetElement("edit-tool-url")?.value?.trim();
      const description = safeGetElement("edit-tool-description")?.value ?? "";

      const integrationType = safeGetElement("edit-tool-type")?.value || "REST";
      const requestTypeField = safeGetElement("edit-tool-request-type");
      const requestType =
        requestTypeField && !requestTypeField.disabled
          ? (requestTypeField.value || "").trim()
          : undefined;

      const headersRaw = safeGetElement("edit-tool-headers")?.value ?? "";
      const schemaRaw = safeGetElement("edit-tool-schema")?.value ?? "";
      const annotationsRaw = safeGetElement("edit-tool-annotations")?.value ?? "";

      const tagsRaw = safeGetElement("edit-tool-tags")?.value ?? "";
      const jsonpathFilter = (safeGetElement("edit-tool-jsonpath-filter")?.value ?? "").toString();

      const visibility = getVisibilityFromEditRadios();

      const inactiveHidden = safeGetElement("edit-show-inactive");
      const isInactiveCheckedVal = inactiveHidden?.value ?? String(isInactiveChecked("tools"));

      // ✅ Build ToolUpdate-ish payload (only fields you want to update)
      const payload = {
        // note: your backend ToolUpdate uses these names (snake_case)
        custom_name: customName || undefined,
        displayName: displayName || undefined,
        url: url || undefined,
        description: description || undefined,
        integration_type: integrationType || undefined,
        request_type: requestType || undefined,
        headers: safeParseJsonOrThrow(headersRaw, "Headers"),
        input_schema: safeParseJsonOrThrow(schemaRaw, "Schema"),
        annotations: safeParseJsonOrThrow(annotationsRaw, "Annotations"),
        jsonpath_filter: jsonpathFilter || undefined,
        tags: normalizeTags(tagsRaw),
        visibility: visibility || undefined,

        // preserve UI behavior
        is_inactive_checked: isInactiveCheckedVal === "true",

        // team_id is usually in hidden input
        team_id: form.querySelector('input[name="team_id"]')?.value || undefined,
      };

      // Optional: if your backend supports updating 'name' directly, include it
      // (Many setups treat name as immutable and use custom_name instead.)
      // If you DO support it, uncomment next line:
      // payload.name = name || undefined;

      const headers = await rbacHeaders();
      const resp = await fetchWithTimeout(`${window.ROOT_PATH}/tools/${toolId}`, {
        method: "PUT",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const { message } = await readBackendMessage(resp);

      if (!resp.ok) {
        throw new Error(message || `Failed to update tool (HTTP ${resp.status})`);
      }

      showSuccessMessage(message || "Tool updated successfully.", statusElId);

      try { closeModal("tool-edit-modal"); } catch (_) {}

      setTimeout(() => window.location.reload(), 350);
    } catch (error) {
      console.error("Edit tool failed:", error);
      showErrorMessage(error?.message || "Failed to update tool.", statusElId);
    } finally {
      if (submitBtn) submitBtn.disabled = false;
    }
  }

  function wire() {
    if (wired) return;
    const form = safeGetElement("edit-tool-form");
    if (!form) return;

    // capture=true so we beat any existing submit listeners
    form.addEventListener("submit", handleEditToolSubmit, true);
    wired = true;
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }
})();


/**
 * SECURE: View Resource function with safe display
 */
async function viewResource(resourceUri) {
    try {
        console.log(`Viewing resource: ${resourceUri}`);

        const response = await fetchWithTimeout(
            `${window.ROOT_PATH}/admin/resources/${encodeURIComponent(resourceUri)}`,
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        const resource = data.resource;
        const content = data.content;

        const resourceDetailsDiv = safeGetElement("resource-details");
        if (resourceDetailsDiv) {
            // Create safe display elements
            const container = document.createElement("div");
            container.className =
                "space-y-2 dark:bg-gray-900 dark:text-gray-100";

            // Add each piece of information safely
            const fields = [
                { label: "URI", value: resource.uri },
                { label: "Name", value: resource.name },
                { label: "Type", value: resource.mimeType || "N/A" },
                { label: "Description", value: resource.description || "N/A" },
            ];

            fields.forEach((field) => {
                const p = document.createElement("p");
                const strong = document.createElement("strong");
                strong.textContent = field.label + ": ";
                p.appendChild(strong);
                p.appendChild(document.createTextNode(field.value));
                container.appendChild(p);
            });

            // Tags section
            const tagsP = document.createElement("p");
            const tagsStrong = document.createElement("strong");
            tagsStrong.textContent = "Tags: ";
            tagsP.appendChild(tagsStrong);

            if (resource.tags && resource.tags.length > 0) {
                resource.tags.forEach((tag) => {
                    const tagSpan = document.createElement("span");
                    tagSpan.className =
                        "inline-block bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full mr-1 mb-1 dark:bg-blue-900 dark:text-blue-200";
                    tagSpan.textContent = tag;
                    tagsP.appendChild(tagSpan);
                });
            } else {
                tagsP.appendChild(document.createTextNode("None"));
            }
            container.appendChild(tagsP);

            // Status with safe styling
            const statusP = document.createElement("p");
            const statusStrong = document.createElement("strong");
            statusStrong.textContent = "Status: ";
            statusP.appendChild(statusStrong);

            const statusSpan = document.createElement("span");
            statusSpan.className = `px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                resource.isActive
                    ? "bg-green-100 text-green-800"
                    : "bg-red-100 text-red-800"
            }`;
            statusSpan.textContent = resource.isActive ? "Active" : "Inactive";
            statusP.appendChild(statusSpan);
            container.appendChild(statusP);

            // Content display - safely handle different types
            const contentDiv = document.createElement("div");
            const contentStrong = document.createElement("strong");
            contentStrong.textContent = "Content:";
            contentDiv.appendChild(contentStrong);

            const contentPre = document.createElement("pre");
            contentPre.className =
                "mt-1 bg-gray-100 p-2 rounded overflow-auto max-h-80 dark:bg-gray-800 dark:text-gray-100";

            // Handle content display - extract actual content from object if needed
            let contentStr = extractContent(
                content,
                resource.description || "No content available",
            );

            if (!contentStr.trim()) {
                contentStr = resource.description || "No content available";
            }

            contentPre.textContent = contentStr;
            contentDiv.appendChild(contentPre);
            container.appendChild(contentDiv);

            // Metrics display
            if (resource.metrics) {
                const metricsDiv = document.createElement("div");
                const metricsStrong = document.createElement("strong");
                metricsStrong.textContent = "Metrics:";
                metricsDiv.appendChild(metricsStrong);

                const metricsList = document.createElement("ul");
                metricsList.className = "list-disc list-inside ml-4";

                const metricsData = [
                    {
                        label: "Total Executions",
                        value: resource.metrics.totalExecutions ?? 0,
                    },
                    {
                        label: "Successful Executions",
                        value: resource.metrics.successfulExecutions ?? 0,
                    },
                    {
                        label: "Failed Executions",
                        value: resource.metrics.failedExecutions ?? 0,
                    },
                    {
                        label: "Failure Rate",
                        value: resource.metrics.failureRate ?? 0,
                    },
                    {
                        label: "Min Response Time",
                        value: resource.metrics.minResponseTime ?? "N/A",
                    },
                    {
                        label: "Max Response Time",
                        value: resource.metrics.maxResponseTime ?? "N/A",
                    },
                    {
                        label: "Average Response Time",
                        value: resource.metrics.avgResponseTime ?? "N/A",
                    },
                    {
                        label: "Last Execution Time",
                        value: resource.metrics.lastExecutionTime ?? "N/A",
                    },
                ];

                metricsData.forEach((metric) => {
                    const li = document.createElement("li");
                    li.textContent = `${metric.label}: ${metric.value}`;
                    metricsList.appendChild(li);
                });

                metricsDiv.appendChild(metricsList);
                container.appendChild(metricsDiv);
            }

            // Add metadata section
            const metadataDiv = document.createElement("div");
            metadataDiv.className = "mt-6 border-t pt-4";

            const metadataTitle = document.createElement("strong");
            metadataTitle.textContent = "Metadata:";
            metadataDiv.appendChild(metadataTitle);

            const metadataGrid = document.createElement("div");
            metadataGrid.className = "grid grid-cols-2 gap-4 mt-2 text-sm";

            const metadataFields = [
                {
                    label: "Created By",
                    value:
                        resource.created_by ||
                        resource.createdBy ||
                        "Legacy Entity",
                },
                {
                    label: "Created At",
                    value:
                        resource.created_at || resource.createdAt
                            ? new Date(
                                  resource.created_at || resource.createdAt,
                              ).toLocaleString()
                            : "Pre-metadata",
                },
                {
                    label: "Created From",
                    value:
                        resource.created_from_ip ||
                        resource.createdFromIp ||
                        "Unknown",
                },
                {
                    label: "Created Via",
                    value:
                        resource.created_via ||
                        resource.createdVia ||
                        "Unknown",
                },
                {
                    label: "Last Modified By",
                    value: resource.modified_by || resource.modifiedBy || "N/A",
                },
                {
                    label: "Last Modified At",
                    value:
                        resource.updated_at || resource.updatedAt
                            ? new Date(
                                  resource.updated_at || resource.updatedAt,
                              ).toLocaleString()
                            : "N/A",
                },
                {
                    label: "Modified From",
                    value:
                        resource.modified_from_ip ||
                        resource.modifiedFromIp ||
                        "N/A",
                },
                {
                    label: "Modified Via",
                    value:
                        resource.modified_via || resource.modifiedVia || "N/A",
                },
                {
                    label: "Version",
                    value: resource.version || "1",
                },
                {
                    label: "Import Batch",
                    value:
                        resource.import_batch_id ||
                        resource.importBatchId ||
                        "N/A",
                },
            ];

            metadataFields.forEach((field) => {
                const fieldDiv = document.createElement("div");

                const labelSpan = document.createElement("span");
                labelSpan.className =
                    "font-medium text-gray-600 dark:text-gray-400";
                labelSpan.textContent = field.label + ":";

                const valueSpan = document.createElement("span");
                valueSpan.className = "ml-2";
                valueSpan.textContent = field.value;

                fieldDiv.appendChild(labelSpan);
                fieldDiv.appendChild(valueSpan);
                metadataGrid.appendChild(fieldDiv);
            });

            metadataDiv.appendChild(metadataGrid);
            container.appendChild(metadataDiv);

            // Replace content safely
            resourceDetailsDiv.innerHTML = "";
            resourceDetailsDiv.appendChild(container);
        }

        openModal("resource-modal");
        console.log("✓ Resource details loaded successfully");
    } catch (error) {
        console.error("Error fetching resource details:", error);
        const errorMessage = handleFetchError(error, "load resource details");
        showErrorMessage(errorMessage);
    }
}

/**
 * SECURE: Edit Resource function with validation
 */
async function editResource(resourceUri) {
    try {
        console.log(`Editing resource: ${resourceUri}`);

        const response = await fetchWithTimeout(
            `${window.ROOT_PATH}/admin/resources/${encodeURIComponent(resourceUri)}`,
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        const resource = data.resource;
        const content = data.content;
        const isInactiveCheckedBool = isInactiveChecked("resources");
        let hiddenField = safeGetElement("edit-resource-show-inactive");
        if (!hiddenField) {
            hiddenField = document.createElement("input");
            hiddenField.type = "hidden";
            hiddenField.name = "is_inactive_checked";
            hiddenField.id = "edit-resource-show-inactive";
            const editForm = safeGetElement("edit-resource-form");
            if (editForm) {
                editForm.appendChild(hiddenField);
            }
        }
        hiddenField.value = isInactiveCheckedBool;

        // Set form action and populate fields with validation
        const editForm = safeGetElement("edit-resource-form");
        if (editForm) {
            editForm.action = `${window.ROOT_PATH}/admin/resources/${encodeURIComponent(resourceUri)}/edit`;
        }

        // Validate inputs
        const nameValidation = validateInputName(resource.name, "resource");
        const uriValidation = validateInputName(resource.uri, "resource URI");

        const uriField = safeGetElement("edit-resource-uri");
        const nameField = safeGetElement("edit-resource-name");
        const descField = safeGetElement("edit-resource-description");
        const mimeField = safeGetElement("edit-resource-mime-type");
        const contentField = safeGetElement("edit-resource-content");

        if (uriField && uriValidation.valid) {
            uriField.value = uriValidation.value;
        }
        if (nameField && nameValidation.valid) {
            nameField.value = nameValidation.value;
        }
        if (descField) {
            descField.value = resource.description || "";
        }
        if (mimeField) {
            mimeField.value = resource.mimeType || "";
        }

        // Set tags field
        const tagsField = safeGetElement("edit-resource-tags");
        if (tagsField) {
            tagsField.value = resource.tags ? resource.tags.join(", ") : "";
        }

        if (contentField) {
            let contentStr = extractContent(
                content,
                resource.description || "No content available",
            );

            if (!contentStr.trim()) {
                contentStr = resource.description || "No content available";
            }

            contentField.value = contentStr;
        }

        // Update CodeMirror editor if it exists
        if (window.editResourceContentEditor) {
            let contentStr = extractContent(
                content,
                resource.description || "No content available",
            );

            if (!contentStr.trim()) {
                contentStr = resource.description || "No content available";
            }

            window.editResourceContentEditor.setValue(contentStr);
            window.editResourceContentEditor.refresh();
        }

        openModal("resource-edit-modal");

        // Refresh editor after modal display
        setTimeout(() => {
            if (window.editResourceContentEditor) {
                window.editResourceContentEditor.refresh();
            }
        }, 100);

        console.log("✓ Resource edit modal loaded successfully");
    } catch (error) {
        console.error("Error fetching resource for editing:", error);
        const errorMessage = handleFetchError(
            error,
            "load resource for editing",
        );
        showErrorMessage(errorMessage);
    }
}

/**
 * SECURE: View Prompt function with safe display
 */
async function viewPrompt(promptName) {
    try {
        console.log(`Viewing prompt: ${promptName}`);

        const response = await fetchWithTimeout(
            `${window.ROOT_PATH}/admin/prompts/${encodeURIComponent(promptName)}`,
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const prompt = await response.json();

        const promptDetailsDiv = safeGetElement("prompt-details");
        if (promptDetailsDiv) {
            // Create safe display container
            const container = document.createElement("div");
            container.className =
                "space-y-2 dark:bg-gray-900 dark:text-gray-100";

            // Basic info fields
            const fields = [
                { label: "Name", value: prompt.name },
                { label: "Description", value: prompt.description || "N/A" },
            ];

            fields.forEach((field) => {
                const p = document.createElement("p");
                const strong = document.createElement("strong");
                strong.textContent = field.label + ": ";
                p.appendChild(strong);
                p.appendChild(document.createTextNode(field.value));
                container.appendChild(p);
            });

            // Tags section
            const tagsP = document.createElement("p");
            const tagsStrong = document.createElement("strong");
            tagsStrong.textContent = "Tags: ";
            tagsP.appendChild(tagsStrong);

            if (prompt.tags && prompt.tags.length > 0) {
                prompt.tags.forEach((tag) => {
                    const tagSpan = document.createElement("span");
                    tagSpan.className =
                        "inline-block bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full mr-1 mb-1 dark:bg-blue-900 dark:text-blue-200";
                    tagSpan.textContent = tag;
                    tagsP.appendChild(tagSpan);
                });
            } else {
                tagsP.appendChild(document.createTextNode("None"));
            }
            container.appendChild(tagsP);

            // Status
            const statusP = document.createElement("p");
            const statusStrong = document.createElement("strong");
            statusStrong.textContent = "Status: ";
            statusP.appendChild(statusStrong);

            const statusSpan = document.createElement("span");
            statusSpan.className = `px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                prompt.isActive
                    ? "bg-green-100 text-green-800"
                    : "bg-red-100 text-red-800"
            }`;
            statusSpan.textContent = prompt.isActive ? "Active" : "Inactive";
            statusP.appendChild(statusSpan);
            container.appendChild(statusP);

            // Template display
            const templateDiv = document.createElement("div");
            const templateStrong = document.createElement("strong");
            templateStrong.textContent = "Template:";
            templateDiv.appendChild(templateStrong);

            const templatePre = document.createElement("pre");
            templatePre.className =
                "mt-1 bg-gray-100 p-2 rounded overflow-auto max-h-80 dark:bg-gray-800 dark:text-gray-100";
            templatePre.textContent = prompt.template || "";
            templateDiv.appendChild(templatePre);
            container.appendChild(templateDiv);

            // Arguments display
            const argsDiv = document.createElement("div");
            const argsStrong = document.createElement("strong");
            argsStrong.textContent = "Arguments:";
            argsDiv.appendChild(argsStrong);

            const argsPre = document.createElement("pre");
            argsPre.className =
                "mt-1 bg-gray-100 p-2 rounded dark:bg-gray-800 dark:text-gray-100";
            argsPre.textContent = JSON.stringify(
                prompt.arguments || {},
                null,
                2,
            );
            argsDiv.appendChild(argsPre);
            container.appendChild(argsDiv);

            // Metrics
            if (prompt.metrics) {
                const metricsDiv = document.createElement("div");
                const metricsStrong = document.createElement("strong");
                metricsStrong.textContent = "Metrics:";
                metricsDiv.appendChild(metricsStrong);

                const metricsList = document.createElement("ul");
                metricsList.className = "list-disc list-inside ml-4";

                const metricsData = [
                    {
                        label: "Total Executions",
                        value: prompt.metrics.totalExecutions ?? 0,
                    },
                    {
                        label: "Successful Executions",
                        value: prompt.metrics.successfulExecutions ?? 0,
                    },
                    {
                        label: "Failed Executions",
                        value: prompt.metrics.failedExecutions ?? 0,
                    },
                    {
                        label: "Failure Rate",
                        value: prompt.metrics.failureRate ?? 0,
                    },
                    {
                        label: "Min Response Time",
                        value: prompt.metrics.minResponseTime ?? "N/A",
                    },
                    {
                        label: "Max Response Time",
                        value: prompt.metrics.maxResponseTime ?? "N/A",
                    },
                    {
                        label: "Average Response Time",
                        value: prompt.metrics.avgResponseTime ?? "N/A",
                    },
                    {
                        label: "Last Execution Time",
                        value: prompt.metrics.lastExecutionTime ?? "N/A",
                    },
                ];

                metricsData.forEach((metric) => {
                    const li = document.createElement("li");
                    li.textContent = `${metric.label}: ${metric.value}`;
                    metricsList.appendChild(li);
                });

                metricsDiv.appendChild(metricsList);
                container.appendChild(metricsDiv);
            }

            // Add metadata section
            const metadataDiv = document.createElement("div");
            metadataDiv.className = "mt-6 border-t pt-4";

            const metadataTitle = document.createElement("strong");
            metadataTitle.textContent = "Metadata:";
            metadataDiv.appendChild(metadataTitle);

            const metadataGrid = document.createElement("div");
            metadataGrid.className = "grid grid-cols-2 gap-4 mt-2 text-sm";

            const metadataFields = [
                {
                    label: "Created By",
                    value:
                        prompt.created_by ||
                        prompt.createdBy ||
                        "Legacy Entity",
                },
                {
                    label: "Created At",
                    value:
                        prompt.created_at || prompt.createdAt
                            ? new Date(
                                  prompt.created_at || prompt.createdAt,
                              ).toLocaleString()
                            : "Pre-metadata",
                },
                {
                    label: "Created From",
                    value:
                        prompt.created_from_ip ||
                        prompt.createdFromIp ||
                        "Unknown",
                },
                {
                    label: "Created Via",
                    value: prompt.created_via || prompt.createdVia || "Unknown",
                },
                {
                    label: "Last Modified By",
                    value: prompt.modified_by || prompt.modifiedBy || "N/A",
                },
                {
                    label: "Last Modified At",
                    value:
                        prompt.updated_at || prompt.updatedAt
                            ? new Date(
                                  prompt.updated_at || prompt.updatedAt,
                              ).toLocaleString()
                            : "N/A",
                },
                {
                    label: "Modified From",
                    value:
                        prompt.modified_from_ip ||
                        prompt.modifiedFromIp ||
                        "N/A",
                },
                {
                    label: "Modified Via",
                    value: prompt.modified_via || prompt.modifiedVia || "N/A",
                },
                { label: "Version", value: prompt.version || "1" },
                { label: "Import Batch", value: prompt.importBatchId || "N/A" },
            ];

            metadataFields.forEach((field) => {
                const fieldDiv = document.createElement("div");

                const labelSpan = document.createElement("span");
                labelSpan.className =
                    "font-medium text-gray-600 dark:text-gray-400";
                labelSpan.textContent = field.label + ":";

                const valueSpan = document.createElement("span");
                valueSpan.className = "ml-2";
                valueSpan.textContent = field.value;

                fieldDiv.appendChild(labelSpan);
                fieldDiv.appendChild(valueSpan);
                metadataGrid.appendChild(fieldDiv);
            });

            metadataDiv.appendChild(metadataGrid);
            container.appendChild(metadataDiv);

            // Replace content safely
            promptDetailsDiv.innerHTML = "";
            promptDetailsDiv.appendChild(container);
        }

        openModal("prompt-modal");
        console.log("✓ Prompt details loaded successfully");
    } catch (error) {
        console.error("Error fetching prompt details:", error);
        const errorMessage = handleFetchError(error, "load prompt details");
        showErrorMessage(errorMessage);
    }
}

/**
 * SECURE: Edit Prompt function with validation
 */
async function editPrompt(promptName) {
    try {
        console.log(`Editing prompt: ${promptName}`);

        const response = await fetchWithTimeout(
            `${window.ROOT_PATH}/admin/prompts/${encodeURIComponent(promptName)}`,
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const prompt = await response.json();

        const isInactiveCheckedBool = isInactiveChecked("prompts");
        let hiddenField = safeGetElement("edit-prompt-show-inactive");
        if (!hiddenField) {
            hiddenField = document.createElement("input");
            hiddenField.type = "hidden";
            hiddenField.name = "is_inactive_checked";
            hiddenField.id = "edit-prompt-show-inactive";
            const editForm = safeGetElement("edit-prompt-form");
            if (editForm) {
                editForm.appendChild(hiddenField);
            }
        }
        hiddenField.value = isInactiveCheckedBool;

        // Set form action and populate fields with validation
        const editForm = safeGetElement("edit-prompt-form");
        if (editForm) {
            editForm.action = `${window.ROOT_PATH}/admin/prompts/${encodeURIComponent(promptName)}/edit`;
        }

        // Validate prompt name
        const nameValidation = validateInputName(prompt.name, "prompt");

        const nameField = safeGetElement("edit-prompt-name");
        const descField = safeGetElement("edit-prompt-description");
        const templateField = safeGetElement("edit-prompt-template");
        const argsField = safeGetElement("edit-prompt-arguments");

        if (nameField && nameValidation.valid) {
            nameField.value = nameValidation.value;
        }
        if (descField) {
            descField.value = prompt.description || "";
        }

        // Set tags field
        const tagsField = safeGetElement("edit-prompt-tags");
        if (tagsField) {
            tagsField.value = prompt.tags ? prompt.tags.join(", ") : "";
        }

        if (templateField) {
            templateField.value = prompt.template || "";
        }

        // Validate arguments JSON
        const argsValidation = validateJson(
            JSON.stringify(prompt.arguments || {}),
            "Arguments",
        );
        if (argsField && argsValidation.valid) {
            argsField.value = JSON.stringify(argsValidation.value, null, 2);
        }

        // Update CodeMirror editors if they exist
        if (window.editPromptTemplateEditor) {
            window.editPromptTemplateEditor.setValue(prompt.template || "");
            window.editPromptTemplateEditor.refresh();
        }
        if (window.editPromptArgumentsEditor && argsValidation.valid) {
            window.editPromptArgumentsEditor.setValue(
                JSON.stringify(argsValidation.value, null, 2),
            );
            window.editPromptArgumentsEditor.refresh();
        }

        openModal("prompt-edit-modal");

        // Refresh editors after modal display
        setTimeout(() => {
            if (window.editPromptTemplateEditor) {
                window.editPromptTemplateEditor.refresh();
            }
            if (window.editPromptArgumentsEditor) {
                window.editPromptArgumentsEditor.refresh();
            }
        }, 100);

        console.log("✓ Prompt edit modal loaded successfully");
    } catch (error) {
        console.error("Error fetching prompt for editing:", error);
        const errorMessage = handleFetchError(error, "load prompt for editing");
        showErrorMessage(errorMessage);
    }
}

async function readBackendMessage(response) {
  let data = null;

  try {
    const ct = (response.headers.get("content-type") || "").toLowerCase();
    if (ct.includes("application/json")) data = await response.json();
    else data = await response.text();
  } catch (_) {
    data = null;
  }

  const isOk = !!response.ok;

  // 1) Plain string body
  if (typeof data === "string") {
    const msg = data.trim();
    return { data, message: msg };
  }

  // 2) JSON object body
  if (data && typeof data === "object") {
    // FastAPI validation errors: {"detail":[{msg:"..."}]}
    if (Array.isArray(data.detail)) {
      const msg = data.detail
        .map((d) => d?.msg || d?.message || "")
        .filter(Boolean)
        .join(" | ");
      return { data, message: msg };
    }

    // Common shapes: {"detail":"..."} or {"message":"..."} or {"error":"..."}
    if (typeof data.detail === "string") return { data, message: data.detail };
    if (typeof data.message === "string") return { data, message: data.message };
    if (typeof data.error === "string") return { data, message: data.error };

    // Sometimes backend wraps: {"detail": {"message":"...", "success":false}}
    if (data.detail && typeof data.detail === "object") {
      if (typeof data.detail.message === "string") return { data, message: data.detail.message };
      if (typeof data.detail.error === "string") return { data, message: data.detail.error };
    }

    // ✅ IMPORTANT FIX:
    // If response is OK and it's an object (like your Server JSON),
    // DO NOT stringify it as a message.
    if (isOk) {
      return { data, message: "" }; // let caller show "updated successfully"
    }

    // If response is NOT ok and we couldn't extract a message,
    // return a safe short fallback (NOT the whole JSON).
    return { data, message: `Request failed (HTTP ${response.status})` };
  }

  // 3) Nothing usable
  return { data, message: isOk ? "" : `Request failed (HTTP ${response.status})` };
}


/**
 * SECURE: View Gateway function
 */
async function viewGateway(gatewayId) {
    try {
        console.log(`Viewing gateway ID: ${gatewayId}`);

        const response = await fetchWithTimeout(
            `${window.ROOT_PATH}/gateways/${gatewayId}`,
        );

        if (!response.ok) {
            const { message } = await readBackendMessage(response);
            throw new Error(message || `Failed to load gateway (HTTP ${response.status})`);
        }
        const { data: gateway } = await readBackendMessage(response);


        const gatewayDetailsDiv = safeGetElement("gateway-details");
        if (gatewayDetailsDiv) {
            const container = document.createElement("div");
            container.className =
                "space-y-2 dark:bg-gray-900 dark:text-gray-100";

            const fields = [
                { label: "Name", value: gateway.name },
                { label: "URL", value: gateway.url },
                { label: "Description", value: gateway.description || "N/A" },
            ];

            // Add tags field with special handling
            const tagsP = document.createElement("p");
            const tagsStrong = document.createElement("strong");
            tagsStrong.textContent = "Tags: ";
            tagsP.appendChild(tagsStrong);
            if (gateway.tags && gateway.tags.length > 0) {
                gateway.tags.forEach((tag, index) => {
                    const tagSpan = document.createElement("span");
                    tagSpan.className =
                        "inline-block bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full mr-1";
                    tagSpan.textContent = tag;
                    tagsP.appendChild(tagSpan);
                });
            } else {
                tagsP.appendChild(document.createTextNode("No tags"));
            }
            container.appendChild(tagsP);

            fields.forEach((field) => {
                const p = document.createElement("p");
                const strong = document.createElement("strong");
                strong.textContent = field.label + ": ";
                p.appendChild(strong);
                p.appendChild(document.createTextNode(field.value));
                container.appendChild(p);
            });

            // Status
            const statusP = document.createElement("p");
            const statusStrong = document.createElement("strong");
            statusStrong.textContent = "Status: ";
            statusP.appendChild(statusStrong);

            const statusSpan = document.createElement("span");
            let statusText = "";
            let statusClass = "";
            let statusIcon = "";
            if (!gateway.enabled) {
                statusText = "Inactive";
                statusClass = "bg-red-100 text-red-800";
                statusIcon = `
                    <svg class="ml-1 h-4 w-4 text-red-600 self-center" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M6.293 6.293a1 1 0 011.414 0L10 8.586l2.293-2.293a1 1 0 111.414 1.414L11.414 10l2.293 2.293a1 1 0 11-1.414 1.414L10 11.414l-2.293 2.293a1 1 0 11-1.414-1.414L8.586 10 6.293 7.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                      </svg>`;
            } else if (gateway.enabled && gateway.reachable) {
                statusText = "Active";
                statusClass = "bg-green-100 text-green-800";
                statusIcon = `
                    <svg class="ml-1 h-4 w-4 text-green-600 self-center" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm-1-4.586l5.293-5.293-1.414-1.414L9 11.586 7.121 9.707 5.707 11.121 9 14.414z" clip-rule="evenodd"></path>
                      </svg>`;
            } else if (gateway.enabled && !gateway.reachable) {
                statusText = "Offline";
                statusClass = "bg-yellow-100 text-yellow-800";
                statusIcon = `
                    <svg class="ml-1 h-4 w-4 text-yellow-600 self-center" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm-1-10h2v4h-2V8zm0 6h2v2h-2v-2z" clip-rule="evenodd"></path>
                      </svg>`;
            }

            statusSpan.className = `px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${statusClass}`;
            statusSpan.innerHTML = `${statusText} ${statusIcon}`;

            statusP.appendChild(statusSpan);
            container.appendChild(statusP);

            // Add metadata section
            const metadataDiv = document.createElement("div");
            metadataDiv.className = "mt-6 border-t pt-4";

            const metadataTitle = document.createElement("strong");
            metadataTitle.textContent = "Metadata:";
            metadataDiv.appendChild(metadataTitle);

            const metadataGrid = document.createElement("div");
            metadataGrid.className = "grid grid-cols-2 gap-4 mt-2 text-sm";

            const metadataFields = [
                {
                    label: "Created By",
                    value:
                        gateway.created_by ||
                        gateway.createdBy ||
                        "Legacy Entity",
                },
                {
                    label: "Created At",
                    value:
                        gateway.created_at || gateway.createdAt
                            ? new Date(
                                  gateway.created_at || gateway.createdAt,
                              ).toLocaleString()
                            : "Pre-metadata",
                },
                {
                    label: "Created From",
                    value:
                        gateway.created_from_ip ||
                        gateway.createdFromIp ||
                        "Unknown",
                },
                {
                    label: "Created Via",
                    value:
                        gateway.created_via || gateway.createdVia || "Unknown",
                },
                {
                    label: "Last Modified By",
                    value: gateway.modified_by || gateway.modifiedBy || "N/A",
                },
                {
                    label: "Last Modified At",
                    value:
                        gateway.updated_at || gateway.updatedAt
                            ? new Date(
                                  gateway.updated_at || gateway.updatedAt,
                              ).toLocaleString()
                            : "N/A",
                },
                {
                    label: "Modified From",
                    value:
                        gateway.modified_from_ip ||
                        gateway.modifiedFromIp ||
                        "N/A",
                },
                {
                    label: "Modified Via",
                    value: gateway.modified_via || gateway.modifiedVia || "N/A",
                },
                { label: "Version", value: gateway.version || "1" },
                {
                    label: "Import Batch",
                    value: gateway.importBatchId || "N/A",
                },
            ];

            metadataFields.forEach((field) => {
                const fieldDiv = document.createElement("div");

                const labelSpan = document.createElement("span");
                labelSpan.className =
                    "font-medium text-gray-600 dark:text-gray-400";
                labelSpan.textContent = field.label + ":";

                const valueSpan = document.createElement("span");
                valueSpan.className = "ml-2";
                valueSpan.textContent = field.value;

                fieldDiv.appendChild(labelSpan);
                fieldDiv.appendChild(valueSpan);
                metadataGrid.appendChild(fieldDiv);
            });

            metadataDiv.appendChild(metadataGrid);
            container.appendChild(metadataDiv);

            gatewayDetailsDiv.innerHTML = "";
            gatewayDetailsDiv.appendChild(container);
        }

        openModal("gateway-modal");
        console.log("✓ Gateway details loaded successfully");
    } catch (error) {
        console.error("Error fetching gateway details:", error);
        const errorMessage = handleFetchError(error, "load gateway details");
        showErrorMessage(errorMessage);
    }
}

/**
 * SECURE: Edit Gateway function
 */
async function editGateway(gatewayId) {
  try {
    console.log(`Editing gateway ID: ${gatewayId}`);

    const response = await fetchWithTimeout(
      `${window.ROOT_PATH}/gateways/${gatewayId}`,
    );

    const { data: gateway, message } = await readBackendMessage(response);

    // If GET failed, show real backend message (permissions, not found, etc.)
    if (!response.ok) {
      throw new Error(message || `Failed to load gateway (HTTP ${response.status})`);
    }

    const isInactiveCheckedBool = isInactiveChecked("gateways");
    let hiddenField = safeGetElement("edit-gateway-show-inactive");
    if (!hiddenField) {
      hiddenField = document.createElement("input");
      hiddenField.type = "hidden";
      hiddenField.name = "is_inactive_checked";
      hiddenField.id = "edit-gateway-show-inactive";
      const editForm = safeGetElement("edit-gateway-form");
      if (editForm) {
        editForm.appendChild(hiddenField);
      }
    }
    hiddenField.value = isInactiveCheckedBool;

    // Set form action (your backend expects PUT on /gateways/{id} via JS intercept)
    const editForm = safeGetElement("edit-gateway-form");
    if (editForm) {
      editForm.action = `${window.ROOT_PATH}/gateways/${gatewayId}`;
    }

    const nameValidation = validateInputName(gateway.name, "gateway");
    const urlValidation = validateUrl(gateway.url);

    const nameField = safeGetElement("edit-gateway-name");
    const urlField = safeGetElement("edit-gateway-url");
    const descField = safeGetElement("edit-gateway-description");

    const transportField = safeGetElement("edit-gateway-transport");

    if (nameField && nameValidation.valid) {
      nameField.value = nameValidation.value;
    }
    if (urlField && urlValidation.valid) {
      urlField.value = urlValidation.value;
    }
    if (descField) {
      descField.value = gateway.description || "";
    }

    // Set tags field
    const tagsField = safeGetElement("edit-gateway-tags");
    if (tagsField) {
      tagsField.value = gateway.tags ? gateway.tags.join(", ") : "";
    }

    const teamId = new URL(window.location.href).searchParams.get("team_id");
    if (teamId) {
      const hiddenInput = document.createElement("input");
      hiddenInput.type = "hidden";
      hiddenInput.name = "team_id";
      hiddenInput.value = teamId;
      editForm.appendChild(hiddenInput);
    }

    const visibility = gateway.visibility;
    const publicRadio = safeGetElement("edit-gateway-visibility-public");
    const teamRadio = safeGetElement("edit-gateway-visibility-team");
    const privateRadio = safeGetElement("edit-gateway-visibility-private");

    if (visibility) {
      if (visibility === "public" && publicRadio) publicRadio.checked = true;
      else if (visibility === "team" && teamRadio) teamRadio.checked = true;
      else if (visibility === "private" && privateRadio) privateRadio.checked = true;
    }

    if (transportField) {
      transportField.value = gateway.transport || "SSE";
    }

    const authTypeField = safeGetElement("auth-type-gw-edit");
    if (authTypeField) {
      authTypeField.value = gateway.authType || "";
    }

    // Auth containers
    const authBasicSection = safeGetElement("auth-basic-fields-gw-edit");
    const authBearerSection = safeGetElement("auth-bearer-fields-gw-edit");
    const authHeadersSection = safeGetElement("auth-headers-fields-gw-edit");
    const authOAuthSection = safeGetElement("auth-oauth-fields-gw-edit");

    // Individual fields
    const authUsernameField = authBasicSection?.querySelector("input[name='auth_username']");
    const authPasswordField = authBasicSection?.querySelector("input[name='auth_password']");
    const authTokenField = authBearerSection?.querySelector("input[name='auth_token']");
    const authHeaderKeyField = authHeadersSection?.querySelector("input[name='auth_header_key']");
    const authHeaderValueField = authHeadersSection?.querySelector("input[name='auth_header_value']");

    // OAuth fields
    const oauthGrantTypeField = safeGetElement("oauth-grant-type-gw-edit");
    const oauthClientIdField = safeGetElement("oauth-client-id-gw-edit");
    const oauthClientSecretField = safeGetElement("oauth-client-secret-gw-edit");
    const oauthTokenUrlField = safeGetElement("oauth-token-url-gw-edit");
    const oauthAuthUrlField = safeGetElement("oauth-authorization-url-gw-edit");
    const oauthRedirectUriField = safeGetElement("oauth-redirect-uri-gw-edit");
    const oauthScopesField = safeGetElement("oauth-scopes-gw-edit");
    const oauthAuthCodeFields = safeGetElement("oauth-auth-code-fields-gw-edit");

    // Hide all auth sections first
    if (authBasicSection) authBasicSection.style.display = "none";
    if (authBearerSection) authBearerSection.style.display = "none";
    if (authHeadersSection) authHeadersSection.style.display = "none";
    if (authOAuthSection) authOAuthSection.style.display = "none";

    switch (gateway.authType) {
      case "basic":
        if (authBasicSection) {
          authBasicSection.style.display = "block";
          if (authUsernameField) authUsernameField.value = gateway.authUsername || "";
          if (authPasswordField) authPasswordField.value = "*****";
        }
        break;

      case "bearer":
        if (authBearerSection) {
          authBearerSection.style.display = "block";
          if (authTokenField) authTokenField.value = gateway.authValue || "";
        }
        break;

      case "authheaders":
        if (authHeadersSection) {
          authHeadersSection.style.display = "block";
          if (authHeaderKeyField) authHeaderKeyField.value = gateway.authHeaderKey || "";
          if (authHeaderValueField) authHeaderValueField.value = "*****";
        }
        break;

      case "oauth":
        if (authOAuthSection) authOAuthSection.style.display = "block";
        if (gateway.oauthConfig) {
          const config = gateway.oauthConfig;

          if (oauthGrantTypeField && config.grant_type) {
            oauthGrantTypeField.value = config.grant_type;
            if (oauthAuthCodeFields) {
              oauthAuthCodeFields.style.display =
                config.grant_type === "authorization_code" ? "block" : "none";
            }
          }
          if (oauthClientIdField && config.client_id) oauthClientIdField.value = config.client_id;
          if (oauthClientSecretField) oauthClientSecretField.value = ""; // don't prefill
          if (oauthTokenUrlField && config.token_url) oauthTokenUrlField.value = config.token_url;
          if (oauthAuthUrlField && config.authorization_url) oauthAuthUrlField.value = config.authorization_url;
          if (oauthRedirectUriField && config.redirect_uri) oauthRedirectUriField.value = config.redirect_uri;

          if (oauthScopesField && Array.isArray(config.scopes)) {
            oauthScopesField.value = config.scopes.join(" ");
          }
        }
        break;

      default:
        break;
    }

    // Handle passthrough headers
    const passthroughHeadersField = safeGetElement("edit-gateway-passthrough-headers");
    if (passthroughHeadersField) {
      passthroughHeadersField.value = Array.isArray(gateway.passthroughHeaders)
        ? gateway.passthroughHeaders.join(", ")
        : "";
    }

    openModal("gateway-edit-modal");
    console.log("✓ Gateway edit modal loaded successfully");
  } catch (error) {
    console.error("Error fetching gateway for editing:", error);
    // show backend message directly (don’t mask it)
    showErrorMessage(error?.message || "Failed to load gateway for editing");
  }
}

// --- Gateway Edit: intercept <form> submit and send PUT via fetch ---
(function wireGatewayEditPut() {
  let wired = false;

  function getGatewayIdFromAction(actionUrl) {
    try {
      const u = new URL(actionUrl, window.location.origin);
      // expected: /gateways/{id} OR /gateways/{id}/edit (older)
      const parts = u.pathname.split("/").filter(Boolean);
      const idx = parts.indexOf("gateways");
      if (idx >= 0 && parts[idx + 1]) return parts[idx + 1];
    } catch (e) {
      // ignore
    }
    return null;
  }

  function normalizeTags(tagsStr) {
    if (!tagsStr) return [];
    return tagsStr
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean)
      .map((t) => t.toLowerCase().replace(/\s+/g, "-"));
  }

  function normalizeCommaList(str) {
    if (!str) return [];
    return str
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }

  // If you don't already have safeJson, keep this (harmless even if unused)
  async function safeJson(resp) {
    try {
      return await resp.json();
    } catch {
      return null;
    }
  }

  async function handleEditGatewaySubmit(event) {
    event.preventDefault();

    const form = event.target;
    const statusElId = "status-gateways"; // you already have this in the panel

    try {
      // action is set by editGateway(): `${ROOT_PATH}/gateways/${gatewayId}`
      const action = form.action || "";
      const gatewayId = getGatewayIdFromAction(action);
      if (!gatewayId) throw new Error("Could not determine gateway id from form action");

      // Build payload using your existing input IDs/names
      const name = safeGetElement("edit-gateway-name")?.value?.trim();
      const url = safeGetElement("edit-gateway-url")?.value?.trim();
      const description = safeGetElement("edit-gateway-description")?.value ?? "";
      const transport = safeGetElement("edit-gateway-transport")?.value ?? "SSE";

      const tagsRaw = safeGetElement("edit-gateway-tags")?.value ?? "";
      const passthroughRaw = safeGetElement("edit-gateway-passthrough-headers")?.value ?? "";

      const visPublic = safeGetElement("edit-gateway-visibility-public")?.checked;
      const visTeam = safeGetElement("edit-gateway-visibility-team")?.checked;
      const visPrivate = safeGetElement("edit-gateway-visibility-private")?.checked;
      const visibility = visPublic ? "public" : visTeam ? "team" : visPrivate ? "private" : undefined;

      // team_id (you were adding from query param)
      const teamId = new URL(window.location.href).searchParams.get("team_id");

      // auth type
      const authType = safeGetElement("auth-type-gw-edit")?.value ?? "";

      // Optional: preserve your "show inactive" state
      const inactiveHidden = safeGetElement("edit-gateway-show-inactive");
      const isInactiveCheckedVal =
        inactiveHidden?.value ?? String(isInactiveChecked("gateways"));

      // Core update payload (match your GatewayUpdate fields)
      const payload = {
        name: name || undefined,
        url: url || undefined,
        description,
        transport,
        tags: normalizeTags(tagsRaw),
        passthrough_headers: normalizeCommaList(passthroughRaw),
        visibility: visibility || undefined,
        team_id: teamId || undefined,
        auth_type: authType || "",
        // keep as string; backend can ignore if not needed
        is_inactive_checked: isInactiveCheckedVal === "true",
      };

      // Auth-specific fields (keep EXACT inputs you already use)
      if (authType === "basic") {
        const u = form.querySelector("input[name='auth_username']")?.value ?? "";
        const p = form.querySelector("input[name='auth_password']")?.value ?? "";
        // If UI uses masked value "*****", don't overwrite stored secret
        payload.auth_username = u || undefined;
        payload.auth_password = p && p !== "*****" ? p : undefined;
      } else if (authType === "bearer") {
        const tok = form.querySelector("input[name='auth_token']")?.value ?? "";
        payload.auth_token = tok && tok !== "*****" ? tok : undefined;
      } else if (authType === "authheaders") {
        // Your UI has dynamic headers + hidden JSON field
        const hiddenJson = safeGetElement("auth-headers-json-gw-edit")?.value ?? "";
        if (hiddenJson && hiddenJson.trim()) {
          // Backend register/update supports auth_headers list of {key,value}
          try {
            payload.auth_headers = JSON.parse(hiddenJson);
          } catch {
            // If parsing fails, fall back to empty and let backend validate
            payload.auth_headers = [];
          }
        } else {
          payload.auth_headers = [];
        }
      } else if (authType === "oauth") {
        // Build oauth_config from your edit fields
        const grantType = safeGetElement("oauth-grant-type-gw-edit")?.value ?? "client_credentials";
        const clientId = safeGetElement("oauth-client-id-gw-edit")?.value ?? "";
        const clientSecret = safeGetElement("oauth-client-secret-gw-edit")?.value ?? "";
        const tokenUrl = safeGetElement("oauth-token-url-gw-edit")?.value ?? "";
        const authorizationUrl = safeGetElement("oauth-authorization-url-gw-edit")?.value ?? "";
        const redirectUri = safeGetElement("oauth-redirect-uri-gw-edit")?.value ?? "";
        const scopesStr = safeGetElement("oauth-scopes-gw-edit")?.value ?? "";

        payload.oauth_config = {
          grant_type: grantType,
          client_id: clientId || undefined,
          // do NOT send empty secret; only send if user actually typed
          client_secret: clientSecret ? clientSecret : undefined,
          token_url: tokenUrl || undefined,
          authorization_url: authorizationUrl || undefined,
          redirect_uri: redirectUri || undefined,
          scopes: scopesStr
            ? scopesStr.split(" ").map((s) => s.trim()).filter(Boolean)
            : [],
          // if you store these flags in edit modal, add here too (optional)
          // store_tokens: !!safeGetElement("...")?.checked,
          // auto_refresh: !!safeGetElement("...")?.checked,
        };
      }

      // Call PUT /gateways/{id}
      const headers = await rbacHeaders();
      const resp = await fetchWithTimeout(`${window.ROOT_PATH}/gateways/${gatewayId}`, {
        method: "PUT",
        headers,
        body: JSON.stringify(payload),
      });

      if (!resp.ok) {
        const err = await safeJson(resp);
        const msg = err?.detail || err?.message || `Failed: HTTP ${resp.status}`;
        throw new Error(msg);
      }

      showSuccessMessage("Gateway updated successfully.", statusElId);

      // Close modal + refresh list (pick whichever you already use)
      try { closeModal("gateway-edit-modal"); } catch (_) {}
      setTimeout(() => window.location.reload(), 350);

    } catch (error) {
      console.error("Edit gateway failed:", error);
      showErrorMessage(error?.message || "Failed to update gateway.", "status-gateways");
    }
  }

  function wire() {
    if (wired) return;
    const form = safeGetElement("edit-gateway-form");
    if (!form) return;
    form.addEventListener("submit", handleEditGatewaySubmit);
    wired = true;
  }

  // Wire now + also when modals get injected later
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }
})();


/**
 * SECURE: View Server function
 */
async function viewServer(serverId) {
    try {
        console.log(`Viewing server ID: ${serverId}`);

        const response = await fetchWithTimeout(
            `${window.ROOT_PATH}/servers/${serverId}`,
        );

            // ✅ Always decode backend message the same way as Gateways
        const { data: server, message } = await readBackendMessage(response);

        // ✅ If GET failed, show real backend message (permissions, not found, etc.)
        if (!response.ok) {
        throw new Error(message || `Failed to load server (HTTP ${response.status})`);
        }

        const serverDetailsDiv = safeGetElement("server-details");
        if (serverDetailsDiv) {
            const container = document.createElement("div");
            container.className =
                "space-y-4 dark:bg-gray-900 dark:text-gray-100";

            // Header section with server name and icon
            const headerDiv = document.createElement("div");
            headerDiv.className =
                "flex items-center space-x-3 pb-4 border-b border-gray-200 dark:border-gray-600";

            if (server.icon) {
                const iconImg = document.createElement("img");
                iconImg.src = server.icon;
                iconImg.alt = `${server.name} icon`;
                iconImg.className = "w-12 h-12 rounded-lg object-cover";
                iconImg.onerror = function () {
                    this.style.display = "none";
                };
                headerDiv.appendChild(iconImg);
            }

            const headerTextDiv = document.createElement("div");
            const serverTitle = document.createElement("h2");
            serverTitle.className =
                "text-xl font-bold text-gray-900 dark:text-gray-100";
            serverTitle.textContent = server.name;
            headerTextDiv.appendChild(serverTitle);

            if (server.description) {
                const serverDesc = document.createElement("p");
                serverDesc.className =
                    "text-sm text-gray-600 dark:text-gray-400 mt-1";
                serverDesc.textContent = server.description;
                headerTextDiv.appendChild(serverDesc);
            }

            headerDiv.appendChild(headerTextDiv);
            container.appendChild(headerDiv);

            // Basic information section
            const basicInfoDiv = document.createElement("div");
            basicInfoDiv.className = "space-y-2";

            const basicInfoTitle = document.createElement("strong");
            basicInfoTitle.textContent = "Basic Information:";
            basicInfoTitle.className =
                "block text-gray-900 dark:text-gray-100 mb-3";
            basicInfoDiv.appendChild(basicInfoTitle);

            const fields = [
                { label: "Server ID", value: server.id },
                { label: "URL", value: getCatalogUrl(server) || "N/A" },
                { label: "Type", value: "Virtual Server" },
            ];

            fields.forEach((field) => {
                const p = document.createElement("p");
                p.className = "text-sm";
                const strong = document.createElement("strong");
                strong.textContent = field.label + ": ";
                strong.className =
                    "font-medium text-gray-700 dark:text-gray-300";
                p.appendChild(strong);
                const valueSpan = document.createElement("span");
                valueSpan.textContent = field.value;
                valueSpan.className = "text-gray-600 dark:text-gray-400";
                p.appendChild(valueSpan);
                basicInfoDiv.appendChild(p);
            });

            container.appendChild(basicInfoDiv);

            // Tags and Status section
            const tagsStatusDiv = document.createElement("div");
            tagsStatusDiv.className =
                "flex items-center justify-between space-y-2";

            // Tags section
            const tagsP = document.createElement("p");
            tagsP.className = "text-sm";
            const tagsStrong = document.createElement("strong");
            tagsStrong.textContent = "Tags: ";
            tagsStrong.className =
                "font-medium text-gray-700 dark:text-gray-300";
            tagsP.appendChild(tagsStrong);

            if (server.tags && server.tags.length > 0) {
                server.tags.forEach((tag) => {
                    const tagSpan = document.createElement("span");
                    tagSpan.className =
                        "inline-block bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full mr-1 mb-1 dark:bg-blue-900 dark:text-blue-200";
                    tagSpan.textContent = tag;
                    tagsP.appendChild(tagSpan);
                });
            } else {
                const noneSpan = document.createElement("span");
                noneSpan.textContent = "None";
                noneSpan.className = "text-gray-500 dark:text-gray-400";
                tagsP.appendChild(noneSpan);
            }

            // Status section
            const statusP = document.createElement("p");
            statusP.className = "text-sm";
            const statusStrong = document.createElement("strong");
            statusStrong.textContent = "Status: ";
            statusStrong.className =
                "font-medium text-gray-700 dark:text-gray-300";
            statusP.appendChild(statusStrong);

            const statusSpan = document.createElement("span");
            statusSpan.className = `px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                server.isActive
                    ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300"
                    : "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300"
            }`;
            statusSpan.textContent = server.isActive ? "Active" : "Inactive";
            statusP.appendChild(statusSpan);

            tagsStatusDiv.appendChild(tagsP);
            tagsStatusDiv.appendChild(statusP);
            container.appendChild(tagsStatusDiv);

            // Associated Tools, Resources, and Prompts section
            const associatedDiv = document.createElement("div");
            associatedDiv.className = "mt-6 border-t pt-4";

            const associatedTitle = document.createElement("strong");
            associatedTitle.textContent = "Associated Items:";
            associatedDiv.appendChild(associatedTitle);

            // Tools section
            if (server.associatedTools && server.associatedTools.length > 0) {
                const toolsSection = document.createElement("div");
                toolsSection.className = "mt-3";

                const toolsLabel = document.createElement("p");
                const toolsStrong = document.createElement("strong");
                toolsStrong.textContent = "Tools: ";
                toolsLabel.appendChild(toolsStrong);

                const toolsList = document.createElement("div");
                toolsList.className = "mt-1 space-y-1";

                server.associatedTools.forEach((toolId) => {
                    const toolItem = document.createElement("div");
                    toolItem.className = "flex items-center space-x-2";

                    const toolBadge = document.createElement("span");
                    toolBadge.className =
                        "inline-block bg-green-100 text-green-800 text-xs px-2 py-1 rounded-full dark:bg-green-900 dark:text-green-200";
                    toolBadge.textContent =
                        window.toolMapping && window.toolMapping[toolId]
                            ? window.toolMapping[toolId]
                            : toolId;

                    const toolIdSpan = document.createElement("span");
                    toolIdSpan.className =
                        "text-xs text-gray-500 dark:text-gray-400";
                    toolIdSpan.textContent = `(${toolId})`;

                    toolItem.appendChild(toolBadge);
                    toolItem.appendChild(toolIdSpan);
                    toolsList.appendChild(toolItem);
                });

                toolsLabel.appendChild(toolsList);
                toolsSection.appendChild(toolsLabel);
                associatedDiv.appendChild(toolsSection);
            }

            // Resources section
            if (
                server.associatedResources &&
                server.associatedResources.length > 0
            ) {
                const resourcesSection = document.createElement("div");
                resourcesSection.className = "mt-3";

                const resourcesLabel = document.createElement("p");
                const resourcesStrong = document.createElement("strong");
                resourcesStrong.textContent = "Resources: ";
                resourcesLabel.appendChild(resourcesStrong);

                const resourcesList = document.createElement("div");
                resourcesList.className = "mt-1 space-y-1";

                server.associatedResources.forEach((resourceId) => {
                    const resourceItem = document.createElement("div");
                    resourceItem.className = "flex items-center space-x-2";

                    const resourceBadge = document.createElement("span");
                    resourceBadge.className =
                        "inline-block bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full dark:bg-blue-900 dark:text-blue-200";
                    resourceBadge.textContent =
                        window.resourceMapping &&
                        window.resourceMapping[resourceId]
                            ? window.resourceMapping[resourceId]
                            : `Resource ${resourceId}`;

                    const resourceIdSpan = document.createElement("span");
                    resourceIdSpan.className =
                        "text-xs text-gray-500 dark:text-gray-400";
                    resourceIdSpan.textContent = `(${resourceId})`;

                    resourceItem.appendChild(resourceBadge);
                    resourceItem.appendChild(resourceIdSpan);
                    resourcesList.appendChild(resourceItem);
                });

                resourcesLabel.appendChild(resourcesList);
                resourcesSection.appendChild(resourcesLabel);
                associatedDiv.appendChild(resourcesSection);
            }

            // Prompts section
            if (
                server.associatedPrompts &&
                server.associatedPrompts.length > 0
            ) {
                const promptsSection = document.createElement("div");
                promptsSection.className = "mt-3";

                const promptsLabel = document.createElement("p");
                const promptsStrong = document.createElement("strong");
                promptsStrong.textContent = "Prompts: ";
                promptsLabel.appendChild(promptsStrong);

                const promptsList = document.createElement("div");
                promptsList.className = "mt-1 space-y-1";

                server.associatedPrompts.forEach((promptId) => {
                    const promptItem = document.createElement("div");
                    promptItem.className = "flex items-center space-x-2";

                    const promptBadge = document.createElement("span");
                    promptBadge.className =
                        "inline-block bg-purple-100 text-purple-800 text-xs px-2 py-1 rounded-full dark:bg-purple-900 dark:text-purple-200";
                    promptBadge.textContent =
                        window.promptMapping && window.promptMapping[promptId]
                            ? window.promptMapping[promptId]
                            : `Prompt ${promptId}`;

                    const promptIdSpan = document.createElement("span");
                    promptIdSpan.className =
                        "text-xs text-gray-500 dark:text-gray-400";
                    promptIdSpan.textContent = `(${promptId})`;

                    promptItem.appendChild(promptBadge);
                    promptItem.appendChild(promptIdSpan);
                    promptsList.appendChild(promptItem);
                });

                promptsLabel.appendChild(promptsList);
                promptsSection.appendChild(promptsLabel);
                associatedDiv.appendChild(promptsSection);
            }

            // A2A Agents section
            if (
                server.associatedA2aAgents &&
                server.associatedA2aAgents.length > 0
            ) {
                const agentsSection = document.createElement("div");
                agentsSection.className = "mt-3";

                const agentsLabel = document.createElement("p");
                const agentsStrong = document.createElement("strong");
                agentsStrong.textContent = "A2A Agents: ";
                agentsLabel.appendChild(agentsStrong);

                const agentsList = document.createElement("div");
                agentsList.className = "mt-1 space-y-1";

                server.associatedA2aAgents.forEach((agentId) => {
                    const agentItem = document.createElement("div");
                    agentItem.className = "flex items-center space-x-2";

                    const agentBadge = document.createElement("span");
                    agentBadge.className =
                        "inline-block bg-orange-100 text-orange-800 text-xs px-2 py-1 rounded-full dark:bg-orange-900 dark:text-orange-200";
                    agentBadge.textContent = `Agent ${agentId}`;

                    const agentIdSpan = document.createElement("span");
                    agentIdSpan.className =
                        "text-xs text-gray-500 dark:text-gray-400";
                    agentIdSpan.textContent = `(${agentId})`;

                    agentItem.appendChild(agentBadge);
                    agentItem.appendChild(agentIdSpan);
                    agentsList.appendChild(agentItem);
                });

                agentsLabel.appendChild(agentsList);
                agentsSection.appendChild(agentsLabel);
                associatedDiv.appendChild(agentsSection);
            }

            // Show message if no associated items
            if (
                (!server.associatedTools ||
                    server.associatedTools.length === 0) &&
                (!server.associatedResources ||
                    server.associatedResources.length === 0) &&
                (!server.associatedPrompts ||
                    server.associatedPrompts.length === 0) &&
                (!server.associatedA2aAgents ||
                    server.associatedA2aAgents.length === 0)
            ) {
                const noItemsP = document.createElement("p");
                noItemsP.className =
                    "mt-2 text-sm text-gray-500 dark:text-gray-400";
                noItemsP.textContent =
                    "No tools, resources, prompts, or A2A agents are currently associated with this server.";
                associatedDiv.appendChild(noItemsP);
            }

            container.appendChild(associatedDiv);

            // Add metadata section
            const metadataDiv = document.createElement("div");
            metadataDiv.className = "mt-6 border-t pt-4";

            const metadataTitle = document.createElement("strong");
            metadataTitle.textContent = "Metadata:";
            metadataDiv.appendChild(metadataTitle);

            const metadataGrid = document.createElement("div");
            metadataGrid.className = "grid grid-cols-2 gap-4 mt-2 text-sm";

            const metadataFields = [
                {
                    label: "Created By",
                    value: server.createdBy || "Legacy Entity",
                },
                {
                    label: "Created At",
                    value: server.createdAt
                        ? new Date(server.createdAt).toLocaleString()
                        : "Pre-metadata",
                },
                {
                    label: "Created From IP",
                    value:
                        server.created_from_ip ||
                        server.createdFromIp ||
                        "Unknown",
                },
                {
                    label: "Created Via",
                    value: server.created_via || server.createdVia || "Unknown",
                },
                {
                    label: "Last Modified By",
                    value: server.modified_by || server.modifiedBy || "N/A",
                },
                {
                    label: "Last Modified At",
                    value: server.updated_at
                        ? new Date(server.updated_at).toLocaleString()
                        : server.updatedAt
                          ? new Date(server.updatedAt).toLocaleString()
                          : "N/A",
                },
                {
                    label: "Modified From IP",
                    value:
                        server.modified_from_ip ||
                        server.modifiedFromIp ||
                        "N/A",
                },
                {
                    label: "Modified Via",
                    value: server.modified_via || server.modifiedVia || "N/A",
                },
                { label: "Version", value: server.version || "1" },
                {
                    label: "Import Batch",
                    value: server.importBatchId || "N/A",
                },
            ];

            metadataFields.forEach((field) => {
                const fieldDiv = document.createElement("div");

                const labelSpan = document.createElement("span");
                labelSpan.className =
                    "font-medium text-gray-600 dark:text-gray-400";
                labelSpan.textContent = field.label + ":";

                const valueSpan = document.createElement("span");
                valueSpan.className = "ml-2";
                valueSpan.textContent = field.value;

                fieldDiv.appendChild(labelSpan);
                fieldDiv.appendChild(valueSpan);
                metadataGrid.appendChild(fieldDiv);
            });

            metadataDiv.appendChild(metadataGrid);
            container.appendChild(metadataDiv);

            serverDetailsDiv.innerHTML = "";
            serverDetailsDiv.appendChild(container);
        }

            openModal("server-modal");
            console.log("✓ Server details loaded successfully");
        } catch (error) {
            console.error("Error fetching server details:", error);
            // ✅ Don't mask the backend message; show it directly
            showErrorMessage(error?.message || "Failed to load server details");
        }
        }

/**
 * SECURE: Edit Server function (Gateway-style)
 * - GET /servers/{id}
 * - populate modal
 * - set form.action = /servers/{id} (PUT will be done by interceptor)
 */
async function editServer(serverId) {
  try {
    console.log(`Editing server ID: ${serverId}`);

    const response = await fetchWithTimeout(`${window.ROOT_PATH}/servers/${serverId}`);
    const { data: server, message } = await readBackendMessage(response);

    if (!response.ok) {
      throw new Error(message || `Failed to load server (HTTP ${response.status})`);
    }

    const isInactiveCheckedBool = isInactiveChecked("servers");
    let hiddenField = safeGetElement("edit-server-show-inactive");
    const editForm = safeGetElement("edit-server-form");

    if (!hiddenField) {
      hiddenField = document.createElement("input");
      hiddenField.type = "hidden";
      hiddenField.name = "is_inactive_checked";
      hiddenField.id = "edit-server-show-inactive";
      if (editForm) editForm.appendChild(hiddenField);
    }
    hiddenField.value = String(isInactiveCheckedBool);

    // Set form action (PUT will be done by interceptor)
    if (editForm) {
      editForm.action = `${window.ROOT_PATH}/servers/${serverId}`;
    }

    // Team id (keep same behavior you had)
    const teamId = new URL(window.location.href).searchParams.get("team_id");
    if (teamId && editForm && !editForm.querySelector('input[name="team_id"]')) {
      const hiddenInput = document.createElement("input");
      hiddenInput.type = "hidden";
      hiddenInput.name = "team_id";
      hiddenInput.value = teamId;
      editForm.appendChild(hiddenInput);
    }

    // Visibility radios
    const visibility = server.visibility;
    const publicRadio = safeGetElement("edit-visibility-public");
    const teamRadio = safeGetElement("edit-visibility-team");
    const privateRadio = safeGetElement("edit-visibility-private");

    if (visibility === "public" && publicRadio) publicRadio.checked = true;
    else if (visibility === "team" && teamRadio) teamRadio.checked = true;
    else if (visibility === "private" && privateRadio) privateRadio.checked = true;

    // Populate fields
    const nameValidation = validateInputName(server.name, "server");

    const nameField = safeGetElement("edit-server-name");
    const descField = safeGetElement("edit-server-description");
    const idField = safeGetElement("edit-server-id");
    const tagsField = safeGetElement("edit-server-tags");
    const iconField = safeGetElement("edit-server-icon");

    if (nameField && nameValidation.valid) nameField.value = nameValidation.value;
    if (descField) descField.value = server.description || "";
    if (idField) idField.value = server.id || "";
    if (tagsField) tagsField.value = Array.isArray(server.tags) ? server.tags.join(", ") : "";
    if (iconField) iconField.value = server.icon || "";

    // Store for modal use
    window.currentEditingServer = server;

    // Open modal
    openModal("server-edit-modal");

    // Set checkboxes (keep your existing logic)
    setEditServerAssociations(server);
    setTimeout(() => setEditServerAssociations(server), 100);
    setTimeout(() => setEditServerAssociations(server), 300);

    console.log("✓ Server edit modal loaded successfully");
  } catch (error) {
    console.error("Error fetching server for editing:", error);
    showErrorMessage(error?.message || "Failed to load server for editing");
  }
}


// --- Server Edit: intercept <form> submit and send PUT via fetch ---
// --- Server Edit: intercept <form> submit and send PUT via fetch (Gateway-style) ---
(function wireServerEditPut() {
  let wired = false;

  function getServerIdFromAction(actionUrl) {
    try {
      const u = new URL(actionUrl, window.location.origin);
      const parts = u.pathname.split("/").filter(Boolean);
      const idx = parts.indexOf("servers");
      if (idx >= 0 && parts[idx + 1]) return parts[idx + 1];
    } catch (_) {}
    return null;
  }

  function normalizeTags(tagsStr) {
    if (!tagsStr) return [];
    return tagsStr
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);
  }

  function uniq(arr) {
    return Array.from(new Set((arr || []).filter(Boolean)));
  }

  function getVisibilityFromEditRadios() {
    const visPublic = safeGetElement("edit-visibility-public")?.checked;
    const visTeam = safeGetElement("edit-visibility-team")?.checked;
    const visPrivate = safeGetElement("edit-visibility-private")?.checked;
    return visPublic ? "public" : visTeam ? "team" : visPrivate ? "private" : undefined;
  }

  function getCheckedValuesByName(name) {
    return Array.from(document.querySelectorAll(`input[name="${name}"]:checked`))
      .map((el) => (el && el.value ? String(el.value).trim() : ""))
      .filter(Boolean);
  }

  async function handleEditServerSubmit(event) {
    // ✅ stop old handler(s) that still try POST
    event.preventDefault();
    event.stopPropagation();
    if (typeof event.stopImmediatePropagation === "function") {
      event.stopImmediatePropagation();
    }

    const form = event.target;
    const statusElId = "status-servers"; // change if your panel uses another id

    // prevent double submit
    const submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');
    if (submitBtn) {
      if (submitBtn.disabled) return;
      submitBtn.disabled = true;
    }

    try {
      const action = form.action || "";
      const serverId = getServerIdFromAction(action);
      if (!serverId) throw new Error("Could not determine server id from form action");

      // Build payload using your current UI fields
      const name = safeGetElement("edit-server-name")?.value?.trim();
      const description = safeGetElement("edit-server-description")?.value ?? "";
      const icon = safeGetElement("edit-server-icon")?.value ?? "";
      const tagsRaw = safeGetElement("edit-server-tags")?.value ?? "";
      const visibility = getVisibilityFromEditRadios();

      // Associated IDs (dedupe to reduce backend dup inserts)
      const toolIds = uniq(getCheckedValuesByName("associatedTools"));
      const resourceIds = uniq(getCheckedValuesByName("associatedResources"));
      const promptIds = uniq(getCheckedValuesByName("associatedPrompts"));

      const inactiveHidden = safeGetElement("edit-server-show-inactive");
      const isInactiveCheckedVal = inactiveHidden?.value ?? String(isInactiveChecked("servers"));

      const payload = {
        id: safeGetElement("edit-server-id")?.value || undefined,
        name: name || undefined,
        description,
        icon,
        tags: normalizeTags(tagsRaw),
        visibility: visibility || undefined,
        team_id: form.querySelector('input[name="team_id"]')?.value || undefined,

        // keep same format your backend currently expects
        associated_tools: toolIds.join(","),
        associated_resources: resourceIds.join(","),
        associated_prompts: promptIds.join(","),

        // preserve include_inactive behavior (if backend uses it)
        is_inactive_checked: isInactiveCheckedVal === "true",
      };

      const headers = await rbacHeaders();
      // ensure JSON content-type for PUT
      const resp = await fetchWithTimeout(`${window.ROOT_PATH}/servers/${serverId}`, {
        method: "PUT",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const { message } = await readBackendMessage(resp);

      if (!resp.ok) {
        // ✅ show only message, not full json
        throw new Error(message || `Failed to update server (HTTP ${resp.status})`);
      }

      showSuccessMessage(message || "Server updated successfully.", statusElId);

      try { closeModal("server-edit-modal"); } catch (_) {}

      setTimeout(() => window.location.reload(), 350);
    } catch (error) {
      console.error("Edit server failed:", error);
      showErrorMessage(error?.message || "Failed to update server.", statusElId);
    } finally {
      if (submitBtn) submitBtn.disabled = false;
    }
  }

  function wire() {
    if (wired) return;
    const form = safeGetElement("edit-server-form");
    if (!form) return;

    // capture=true helps us win over any previously attached listeners
    form.addEventListener("submit", handleEditServerSubmit, true);
    wired = true;
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }
})();


/**
 * SECURE: Edit Server function
 */
async function handleEditServerFormSubmit(e) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);

    try {
        // Validate inputs
        const name = formData.get("name");
        const nameValidation = validateInputName(name, "server");
        if (!nameValidation.valid) {
            throw new Error(nameValidation.error);
        }

        // Save CodeMirror editors' contents if present
        if (window.promptToolHeadersEditor) {
            window.promptToolHeadersEditor.save();
        }
        if (window.promptToolSchemaEditor) {
            window.promptToolSchemaEditor.save();
        }

        const isInactiveCheckedBool = isInactiveChecked("servers");
        formData.append("is_inactive_checked", isInactiveCheckedBool);

        // Submit via fetch
        const response = await fetch(form.action, {
            method: "POST",
            body: formData,
        });
        const result = await response.json();
        if (!result || !result.success) {
            throw new Error(result?.message || "Failed to edit server");
        }
        // Only redirect on success
        else {
            // Redirect to the appropriate page based on inactivity checkbox
            const teamId = new URL(window.location.href).searchParams.get(
                "team_id",
            );

            const searchParams = new URLSearchParams();
            if (isInactiveCheckedBool) {
                searchParams.set("include_inactive", "true");
            }
            if (teamId) {
                searchParams.set("team_id", teamId);
            }
            const queryString = searchParams.toString();
            const redirectUrl = `${window.ROOT_PATH}/admin${queryString ? `?${queryString}` : ""}#catalog`;
            window.location.href = redirectUrl;
        }
    } catch (error) {
        console.error("Error:", error);
        showErrorMessage(error.message);
    }
}

// Helper function to set edit server associations
function setEditServerAssociations(server) {
    // Set associated tools checkboxes
    const toolCheckboxes = document.querySelectorAll(
        'input[name="associatedTools"]',
    );

    if (toolCheckboxes.length === 0) {
        return;
    }

    toolCheckboxes.forEach((checkbox) => {
        let isChecked = false;
        if (server.associatedTools && window.toolMapping) {
            // Get the tool name for this checkbox UUID
            const toolName = window.toolMapping[checkbox.value];

            // Check if this tool name is in the associated tools array
            isChecked = toolName && server.associatedTools.includes(toolName);
        }

        checkbox.checked = isChecked;
    });

    // Set associated resources checkboxes
    const resourceCheckboxes = document.querySelectorAll(
        'input[name="associatedResources"]',
    );

    resourceCheckboxes.forEach((checkbox) => {
        const checkboxValue = parseInt(checkbox.value);
        const isChecked =
            server.associatedResources &&
            server.associatedResources.includes(checkboxValue);
        checkbox.checked = isChecked;
    });

    // Set associated prompts checkboxes
    const promptCheckboxes = document.querySelectorAll(
        'input[name="associatedPrompts"]',
    );

    promptCheckboxes.forEach((checkbox) => {
        const checkboxValue = parseInt(checkbox.value);
        const isChecked =
            server.associatedPrompts &&
            server.associatedPrompts.includes(checkboxValue);
        checkbox.checked = isChecked;
    });

    // Force update the pill displays by triggering change events
    setTimeout(() => {
        const allCheckboxes = [
            ...document.querySelectorAll(
                '#edit-server-tools input[type="checkbox"]',
            ),
            ...document.querySelectorAll(
                '#edit-server-resources input[type="checkbox"]',
            ),
            ...document.querySelectorAll(
                '#edit-server-prompts input[type="checkbox"]',
            ),
        ];

        allCheckboxes.forEach((checkbox) => {
            if (checkbox.checked) {
                checkbox.dispatchEvent(new Event("change", { bubbles: true }));
            }
        });
    }, 50);
}

// ===================================================================
// ENHANCED TAB HANDLING with Better Error Management
// ===================================================================

let tabSwitchTimeout = null;

function showTab(tabName) {
    try {
        console.log(`Switching to tab: ${tabName}`);

        // Clear any pending tab switch
        if (tabSwitchTimeout) {
            clearTimeout(tabSwitchTimeout);
        }

        // Navigation styling (immediate)
        document.querySelectorAll(".tab-panel").forEach((p) => {
            if (p) {
                p.classList.add("hidden");
            }
        });

        document.querySelectorAll(".tab-link").forEach((l) => {
            if (l) {
                l.classList.remove(
                    "figma-nav-selected",
                    "figma-blue-border",
                    "figma-blue-txt",
                    "dark:figma-blue-txt",
                    "dark:border-indigo-400",
                );
                l.classList.add(
                    "border-transparent",
                    "text-gray-500",
                    "dark:text-gray-400",
                );
            }
        });

        // Reveal chosen panel
        const panel = safeGetElement(`${tabName}-panel`);
        if (panel) {
            panel.classList.remove("hidden");
        } else {
            console.error(`Panel ${tabName}-panel not found`);
            return;
        }

        const nav = document.querySelector(`[href="#${tabName}"]`);
        if (nav) {
            nav.classList.add(
                "figma-nav-selected",
                "figma-blue-border",
                "figma-blue-txt",
                "dark:figma-blue-txt",
                "dark:border-indigo-400",
            );
            nav.classList.remove(
                "border-transparent",
                "text-gray-500",
                "dark:text-gray-400",
            );
        }

        // Debounced content loading
        tabSwitchTimeout = setTimeout(() => {
            try {
                if (tabName === "metrics") {
                    // Only load if we're still on the metrics tab
                    if (!panel.classList.contains("hidden")) {
                        loadAggregatedMetrics();
                    }
                }

                if (tabName === "rbac") {
                    // Initialize RBAC panel when tab is shown
                    if (!panel.classList.contains("hidden")) {
                        console.log("🔄 Initializing RBAC tab content");
                        try {
                            // Call RBAC initializer if present (JSON + admin.js rendering)
                            if (typeof initializeRBACPanel === "function") {
                                // Only initialize once unless you want refresh behavior
                                const rbacPanel = safeGetElement("rbac-panel");
                                if (rbacPanel && !rbacPanel.hasAttribute("data-setup")) {
                                    initializeRBACPanel();
                                    rbacPanel.setAttribute("data-setup", "true");
                                } else if (rbacPanel) {
                                    // Optional: on revisit, just ensure the current subtab is visible
                                    if (typeof showRBACSubTab === "function") {
                                        // Default fallback to Roles (or My Access inside init)
                                        showRBACSubTab(window.__rbacActiveSubTab || "rbac-roles");
                                    }
                                }
                            } else {
                                console.warn("initializeRBACPanel function not found");
                            }
                        } catch (error) {
                            console.error("Error initializing RBAC panel:", error);
                            showErrorMessage("Failed to initialize RBAC panel");
                        }
                    }
                }

                if (tabName === "teams") {
                    const teamsList = safeGetElement("teams-list");
                    if (teamsList && !panel.classList.contains("hidden")) {
                        const activeFilter = document.querySelector(
                            "#teams-panel .filter-btn.active",
                        );
                        const filterType = activeFilter?.dataset?.filter || "all";
                        loadTeamsByRelationship(filterType);
                    }
                }

                if (tabName === "tokens" || tabName === "tokens-panel") {
                    // Load Tokens list and set up form handling
                    const tokensList = safeGetElement("tokens-list");
                    if (tokensList) {
                        const hasLoadingMessage =
                            tokensList.innerHTML.includes("Loading tokens...");
                        const isEmpty = tokensList.innerHTML.trim() === "";
                        if (hasLoadingMessage || isEmpty) {
                            loadTokensList();
                        }
                    }

                    // Set up create token form if not already set up
                    const createForm = safeGetElement("create-token-form");
                    if (createForm && !createForm.hasAttribute("data-setup")) {
                        setupCreateTokenForm();
                        createForm.setAttribute("data-setup", "true");
                    }
                    loadTeamsForTokenDropdown();

                    const btnLoadTeamTokens = safeGetElement("btn-load-team-tokens");
                    if (btnLoadTeamTokens && !btnLoadTeamTokens.hasAttribute("data-setup")) {
                    btnLoadTeamTokens.addEventListener("click", async () => {
                        await loadTeamTokensList();
                    });
                    btnLoadTeamTokens.setAttribute("data-setup", "true");
                    }

                    const teamSelect = safeGetElement("team-token-team-select");
                    if (teamSelect && !teamSelect.hasAttribute("data-setup")) {
                    teamSelect.addEventListener("change", async () => {
                        // optional: auto load on selection
                        await loadTeamTokensList();
                    });
                    teamSelect.setAttribute("data-setup", "true");
                    }


                }
                // ✅ Add this new block inside the debounced content loading section

                if (tabName === "a2a-agents") {
                    // Load A2A agents list if not already loaded
                    const agentsList = safeGetElement("a2a-agents-list");
                    if (agentsList && agentsList.innerHTML.trim() === "") {
                        // Trigger HTMX load manually if HTMX is available
                        if (window.htmx && window.htmx.trigger) {
                            window.htmx.trigger(agentsList, "load");
                        }
                    }
                }

                if (tabName === "version-info") {
                    const versionPanel = safeGetElement("version-info-panel");
                    if (versionPanel && versionPanel.innerHTML.trim() === "") {
                        fetchWithTimeout(
                            `${window.ROOT_PATH}/version?partial=true`,
                            {},
                            window.MCPGATEWAY_UI_TOOL_TEST_TIMEOUT || 60000,
                        )
                            .then((resp) => {
                                if (!resp.ok) {
                                    throw new Error(
                                        `HTTP ${resp.status}: ${resp.statusText}`,
                                    );
                                }
                                return resp.text();
                            })
                            .then((html) => {
                                safeSetInnerHTML(versionPanel, html, true);
                                console.log("✓ Version info loaded");
                            })
                            .catch((err) => {
                                console.error(
                                    "Failed to load version info:",
                                    err,
                                );
                                const errorDiv = document.createElement("div");
                                errorDiv.className = "text-red-600 p-4";
                                errorDiv.textContent =
                                    "Failed to load version info. Please try again.";
                                versionPanel.innerHTML = "";
                                versionPanel.appendChild(errorDiv);
                            });
                    }
                }

                if (tabName === "export-import") {
                    // Initialize export/import functionality when tab is shown
                    if (!panel.classList.contains("hidden")) {
                        console.log(
                            "🔄 Initializing export/import tab content",
                        );
                        try {
                            // Ensure the export/import functionality is initialized
                            if (typeof initializeExportImport === "function") {
                                initializeExportImport();
                            }
                            // Load recent imports
                            if (typeof loadRecentImports === "function") {
                                loadRecentImports();
                            }
                        } catch (error) {
                            console.error(
                                "Error loading export/import content:",
                                error,
                            );
                        }
                    }
                }

                if (tabName === "permissions") {
                    // Initialize permissions panel when tab is shown
                    if (!panel.classList.contains("hidden")) {
                        console.log("🔄 Initializing permissions tab content");
                        try {
                            // Check if initializePermissionsPanel function exists
                            if (
                                typeof initializePermissionsPanel === "function"
                            ) {
                                initializePermissionsPanel();
                            } else {
                                console.warn(
                                    "initializePermissionsPanel function not found",
                                );
                            }
                        } catch (error) {
                            console.error(
                                "Error initializing permissions panel:",
                                error,
                            );
                        }
                    }
                }
            } catch (error) {
                console.error(
                    `Error in tab ${tabName} content loading:`,
                    error,
                );
            }
        }, 300); // 300ms debounce

        console.log(`✓ Successfully switched to tab: ${tabName}`);
    } catch (error) {
        console.error(`Error switching to tab ${tabName}:`, error);
        showErrorMessage(`Failed to switch to ${tabName} tab`);
    }
}

// ===================================================================
// AUTH HANDLING
// ===================================================================

function handleAuthTypeSelection(
    value,
    basicFields,
    bearerFields,
    headersFields,
    oauthFields,
) {
    if (!basicFields || !bearerFields || !headersFields) {
        console.warn("Auth field elements not found");
        return;
    }

    // Hide all fields first
    [basicFields, bearerFields, headersFields].forEach((field) => {
        if (field) {
            field.style.display = "none";
        }
    });

    // Hide OAuth fields if they exist
    if (oauthFields) {
        oauthFields.style.display = "none";
    }

    // Show relevant field based on selection
    switch (value) {
        case "basic":
            if (basicFields) {
                basicFields.style.display = "block";
            }
            break;
        case "bearer":
            if (bearerFields) {
                bearerFields.style.display = "block";
            }
            break;
        case "authheaders": {
            if (headersFields) {
                headersFields.style.display = "block";
                // Ensure at least one header row is present
                const containerId =
                    headersFields.querySelector('[id$="-container"]')?.id;
                if (containerId) {
                    const container = document.getElementById(containerId);
                    if (container && container.children.length === 0) {
                        addAuthHeader(containerId);
                    }
                }
            }
            break;
        }
        case "oauth":
            if (oauthFields) {
                oauthFields.style.display = "block";
            }
            break;
        default:
            // All fields already hidden
            break;
    }
}

// ===================================================================
// ENHANCED SCHEMA GENERATION with Safe State Access
// ===================================================================

function generateSchema() {
    const schema = {
        title: "CustomInputSchema",
        type: "object",
        properties: {},
        required: [],
    };

    const paramCount = AppState.getParameterCount();

    for (let i = 1; i <= paramCount; i++) {
        try {
            const nameField = document.querySelector(
                `[name="param_name_${i}"]`,
            );
            const typeField = document.querySelector(
                `[name="param_type_${i}"]`,
            );
            const descField = document.querySelector(
                `[name="param_description_${i}"]`,
            );
            const requiredField = document.querySelector(
                `[name="param_required_${i}"]`,
            );

            if (nameField && nameField.value.trim() !== "") {
                // Validate parameter name
                const nameValidation = validateInputName(
                    nameField.value.trim(),
                    "parameter",
                );
                if (!nameValidation.valid) {
                    console.warn(
                        `Invalid parameter name at index ${i}: ${nameValidation.error}`,
                    );
                    continue;
                }

                schema.properties[nameValidation.value] = {
                    type: typeField ? typeField.value : "string",
                    description: descField ? descField.value.trim() : "",
                };

                if (requiredField && requiredField.checked) {
                    schema.required.push(nameValidation.value);
                }
            }
        } catch (error) {
            console.error(`Error processing parameter ${i}:`, error);
        }
    }

    return JSON.stringify(schema, null, 2);
}

function updateSchemaPreview() {
    try {
        const modeRadio = document.querySelector(
            'input[name="schema_input_mode"]:checked',
        );
        if (modeRadio && modeRadio.value === "json") {
            if (
                window.schemaEditor &&
                typeof window.schemaEditor.setValue === "function"
            ) {
                window.schemaEditor.setValue(generateSchema());
            }
        }
    } catch (error) {
        console.error("Error updating schema preview:", error);
    }
}

// ===================================================================
// ENHANCED PARAMETER HANDLING with Validation
// ===================================================================

function handleAddParameter() {
    const parameterCount = AppState.incrementParameterCount();
    const parametersContainer = safeGetElement("parameters-container");

    if (!parametersContainer) {
        console.error("Parameters container not found");
        AppState.decrementParameterCount(); // Rollback
        return;
    }

    try {
        const paramDiv = document.createElement("div");
        paramDiv.classList.add(
            "border",
            "p-4",
            "mb-4",
            "rounded-md",
            "bg-gray-50",
            "shadow-sm",
        );

        // Create parameter form with validation
        const parameterForm = createParameterForm(parameterCount);
        paramDiv.appendChild(parameterForm);

        parametersContainer.appendChild(paramDiv);
        updateSchemaPreview();

        // Delete parameter functionality with safe state management
        const deleteButton = paramDiv.querySelector(".delete-param");
        if (deleteButton) {
            deleteButton.addEventListener("click", () => {
                try {
                    paramDiv.remove();
                    AppState.decrementParameterCount();
                    updateSchemaPreview();
                    console.log(
                        `✓ Removed parameter, count now: ${AppState.getParameterCount()}`,
                    );
                } catch (error) {
                    console.error("Error removing parameter:", error);
                }
            });
        }

        console.log(`✓ Added parameter ${parameterCount}`);
    } catch (error) {
        console.error("Error adding parameter:", error);
        AppState.decrementParameterCount(); // Rollback on error
    }
}

function createParameterForm(parameterCount) {
    const container = document.createElement("div");

    // Header with delete button
    const header = document.createElement("div");
    header.className = "flex justify-between items-center";

    const title = document.createElement("span");
    title.className = "font-semibold text-gray-800 dark:text-gray-200";
    title.textContent = `Parameter ${parameterCount}`;

    const deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.className =
        "delete-param text-red-600 hover:text-red-800 focus:outline-none text-xl";
    deleteBtn.title = "Delete Parameter";
    deleteBtn.textContent = "×";

    header.appendChild(title);
    header.appendChild(deleteBtn);
    container.appendChild(header);

    // Form fields grid
    const grid = document.createElement("div");
    grid.className = "grid grid-cols-1 md:grid-cols-2 gap-4 mt-4";

    // Parameter name field with validation
    const nameGroup = document.createElement("div");
    const nameLabel = document.createElement("label");
    nameLabel.className =
        "block text-sm font-medium text-gray-700 dark:text-gray-300";
    nameLabel.textContent = "Parameter Name";

    const nameInput = document.createElement("input");
    nameInput.type = "text";
    nameInput.name = `param_name_${parameterCount}`;
    nameInput.required = true;
    nameInput.className =
        "mt-1 textfield border border-gray-300 shadow-sm focus:figma-blue-border focus:ring focus:ring-indigo-200";

    // Add validation to name input
    nameInput.addEventListener("blur", function () {
        const validation = validateInputName(this.value, "parameter");
        if (!validation.valid) {
            this.setCustomValidity(validation.error);
            this.reportValidity();
        } else {
            this.setCustomValidity("");
            this.value = validation.value; // Use cleaned value
        }
    });

    nameGroup.appendChild(nameLabel);
    nameGroup.appendChild(nameInput);

    // Type field
    const typeGroup = document.createElement("div");
    const typeLabel = document.createElement("label");
    typeLabel.className =
        "block text-sm font-medium text-gray-700 dark:text-gray-300";
    typeLabel.textContent = "Type";

    const typeSelect = document.createElement("select");
    typeSelect.name = `param_type_${parameterCount}`;
    typeSelect.className =
        "mt-1 selectfield rounded-md border border-gray-300 shadow-sm focus:figma-blue-border focus:ring focus:ring-indigo-200";

    const typeOptions = [
        { value: "string", text: "String" },
        { value: "number", text: "Number" },
        { value: "boolean", text: "Boolean" },
        { value: "object", text: "Object" },
        { value: "array", text: "Array" },
    ];

    typeOptions.forEach((option) => {
        const optionElement = document.createElement("option");
        optionElement.value = option.value;
        optionElement.textContent = option.text;
        typeSelect.appendChild(optionElement);
    });

    typeGroup.appendChild(typeLabel);
    typeGroup.appendChild(typeSelect);

    grid.appendChild(nameGroup);
    grid.appendChild(typeGroup);
    container.appendChild(grid);

    // Description field
    const descGroup = document.createElement("div");
    descGroup.className = "mt-4";

    const descLabel = document.createElement("label");
    descLabel.className =
        "block text-sm font-medium text-gray-700 dark:text-gray-300";
    descLabel.textContent = "Description";

    const descTextarea = document.createElement("textarea");
    descTextarea.name = `param_description_${parameterCount}`;
    descTextarea.className =
        "mt-1 block w-full rounded-md border border-gray-300 shadow-sm focus:figma-blue-border focus:ring focus:ring-indigo-200";
    descTextarea.rows = 2;

    descGroup.appendChild(descLabel);
    descGroup.appendChild(descTextarea);
    container.appendChild(descGroup);

    // Required checkbox
    const requiredGroup = document.createElement("div");
    requiredGroup.className = "mt-4 flex items-center";

    const requiredInput = document.createElement("input");
    requiredInput.type = "checkbox";
    requiredInput.name = `param_required_${parameterCount}`;
    requiredInput.checked = true;
    requiredInput.className =
        "h-4 w-4 figma-blue-txt border border-gray-300 rounded";

    const requiredLabel = document.createElement("label");
    requiredLabel.className =
        "ml-2 text-sm font-medium text-gray-700 dark:text-gray-300";
    requiredLabel.textContent = "Required";

    requiredGroup.appendChild(requiredInput);
    requiredGroup.appendChild(requiredLabel);
    container.appendChild(requiredGroup);

    return container;
}

// ===================================================================
// INTEGRATION TYPE HANDLING
// ===================================================================

const integrationRequestMap = {
    REST: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    MCP: [],
};

function updateRequestTypeOptions(preselectedValue = null) {
    const requestTypeSelect = safeGetElement("requestType");
    const integrationTypeSelect = safeGetElement("integrationType");

    if (!requestTypeSelect || !integrationTypeSelect) {
        return;
    }

    const selectedIntegration = integrationTypeSelect.value;
    const options = integrationRequestMap[selectedIntegration] || [];

    // Clear current options
    requestTypeSelect.innerHTML = "";

    // Add new options
    options.forEach((value) => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = value;
        requestTypeSelect.appendChild(option);
    });

    // Set the value if preselected
    if (preselectedValue && options.includes(preselectedValue)) {
        requestTypeSelect.value = preselectedValue;
    }
}

function updateEditToolRequestTypes(selectedMethod = null) {
    const editToolTypeSelect = safeGetElement("edit-tool-type");
    const editToolRequestTypeSelect = safeGetElement("edit-tool-request-type");
    if (!editToolTypeSelect || !editToolRequestTypeSelect) {
        return;
    }

    // Track previous value using a data attribute
    if (!editToolTypeSelect.dataset.prevValue) {
        editToolTypeSelect.dataset.prevValue = editToolTypeSelect.value;
    }

    // const prevType = editToolTypeSelect.dataset.prevValue;
    const selectedType = editToolTypeSelect.value;
    const allowedMethods = integrationRequestMap[selectedType] || [];

    // If this integration has no HTTP verbs (MCP), clear & disable the control
    if (allowedMethods.length === 0) {
        editToolRequestTypeSelect.innerHTML = "";
        editToolRequestTypeSelect.value = "";
        editToolRequestTypeSelect.disabled = true;
        return;
    }

    // Otherwise populate and enable
    editToolRequestTypeSelect.disabled = false;
    editToolRequestTypeSelect.innerHTML = "";
    allowedMethods.forEach((method) => {
        const option = document.createElement("option");
        option.value = method;
        option.textContent = method;
        editToolRequestTypeSelect.appendChild(option);
    });

    if (selectedMethod && allowedMethods.includes(selectedMethod)) {
        editToolRequestTypeSelect.value = selectedMethod;
    }
}

// ===================================================================
// TOOL SELECT FUNCTIONALITY
// ===================================================================

// Prevent manual REST→MCP changes in edit-tool-form
document.addEventListener("DOMContentLoaded", function () {
    const editToolTypeSelect = document.getElementById("edit-tool-type");
    if (editToolTypeSelect) {
        // Store the initial value for comparison
        editToolTypeSelect.dataset.prevValue = editToolTypeSelect.value;

        editToolTypeSelect.addEventListener("change", function (e) {
            const prevType = this.dataset.prevValue;
            const selectedType = this.value;
            if (prevType === "REST" && selectedType === "MCP") {
                alert("You cannot change integration type from REST to MCP.");
                this.value = prevType;
                // Optionally, reset any dependent fields here
            } else {
                this.dataset.prevValue = selectedType;
            }
        });
    }
});
//= ==================================================================
function initToolSelect(
    selectId,
    pillsId,
    warnId,
    max = 6,
    selectBtnId = null,
    clearBtnId = null,
) {
    const container = document.getElementById(selectId);
    const pillsBox = document.getElementById(pillsId);
    const warnBox = document.getElementById(warnId);
    const clearBtn = clearBtnId ? document.getElementById(clearBtnId) : null;
    const selectBtn = selectBtnId ? document.getElementById(selectBtnId) : null;

    if (!container || !pillsBox || !warnBox) {
        console.warn(
            `Tool select elements not found: ${selectId}, ${pillsId}, ${warnId}`,
        );
        return;
    }

    const checkboxes = container.querySelectorAll('input[type="checkbox"]');
    const pillClasses =
        "inline-block px-3 py-1 text-xs font-semibold text-indigo-700 bg-indigo-100 rounded-full shadow";

    function update() {
        try {
            const checked = Array.from(checkboxes).filter((cb) => cb.checked);
            const count = checked.length;

            // Rebuild pills safely
            pillsBox.innerHTML = "";
            checked.forEach((cb) => {
                const span = document.createElement("span");
                span.className = pillClasses;
                span.textContent =
                    cb.nextElementSibling?.textContent?.trim() || "Unnamed";
                pillsBox.appendChild(span);
            });

            // Warning when > max
            if (count > max) {
                warnBox.textContent = `Selected ${count} tools. Selecting more than ${max} tools can degrade agent performance with the server.`;
            } else {
                warnBox.textContent = "";
            }
        } catch (error) {
            console.error("Error updating tool select:", error);
        }
    }

    if (clearBtn) {
        clearBtn.addEventListener("click", () => {
            checkboxes.forEach((cb) => (cb.checked = false));
            update();
        });
    }

    if (selectBtn) {
        selectBtn.addEventListener("click", () => {
            checkboxes.forEach((cb) => (cb.checked = true));
            update();
        });
    }

    update(); // Initial render
    checkboxes.forEach((cb) => cb.addEventListener("change", update));
}

function initResourceSelect(
    selectId,
    pillsId,
    warnId,
    max = 10,
    selectBtnId = null,
    clearBtnId = null,
) {
    const container = document.getElementById(selectId);
    const pillsBox = document.getElementById(pillsId);
    const warnBox = document.getElementById(warnId);
    const clearBtn = clearBtnId ? document.getElementById(clearBtnId) : null;
    const selectBtn = selectBtnId ? document.getElementById(selectBtnId) : null;

    if (!container || !pillsBox || !warnBox) {
        console.warn(
            `Resource select elements not found: ${selectId}, ${pillsId}, ${warnId}`,
        );
        return;
    }

    const checkboxes = container.querySelectorAll('input[type="checkbox"]');
    const pillClasses =
        "inline-block px-3 py-1 text-xs font-semibold text-blue-700 bg-blue-100 rounded-full shadow dark:text-blue-300 dark:bg-blue-900";

    function update() {
        try {
            const checked = Array.from(checkboxes).filter((cb) => cb.checked);
            const count = checked.length;

            // Rebuild pills safely
            pillsBox.innerHTML = "";
            checked.forEach((cb) => {
                const span = document.createElement("span");
                span.className = pillClasses;
                span.textContent =
                    cb.nextElementSibling?.textContent?.trim() || "Unnamed";
                pillsBox.appendChild(span);
            });

            // Warning when > max
            if (count > max) {
                warnBox.textContent = `Selected ${count} resources. Selecting more than ${max} resources can degrade agent performance with the server.`;
            } else {
                warnBox.textContent = "";
            }
        } catch (error) {
            console.error("Error updating resource select:", error);
        }
    }

    if (clearBtn) {
        clearBtn.addEventListener("click", () => {
            checkboxes.forEach((cb) => (cb.checked = false));
            update();
        });
    }

    if (selectBtn) {
        selectBtn.addEventListener("click", () => {
            checkboxes.forEach((cb) => (cb.checked = true));
            update();
        });
    }

    update(); // Initial render
    checkboxes.forEach((cb) => cb.addEventListener("change", update));
}

function initPromptSelect(
    selectId,
    pillsId,
    warnId,
    max = 8,
    selectBtnId = null,
    clearBtnId = null,
) {
    const container = document.getElementById(selectId);
    const pillsBox = document.getElementById(pillsId);
    const warnBox = document.getElementById(warnId);
    const clearBtn = clearBtnId ? document.getElementById(clearBtnId) : null;
    const selectBtn = selectBtnId ? document.getElementById(selectBtnId) : null;

    if (!container || !pillsBox || !warnBox) {
        console.warn(
            `Prompt select elements not found: ${selectId}, ${pillsId}, ${warnId}`,
        );
        return;
    }

    const checkboxes = container.querySelectorAll('input[type="checkbox"]');
    const pillClasses =
        "inline-block px-3 py-1 text-xs font-semibold text-purple-700 bg-purple-100 rounded-full shadow dark:text-purple-300 dark:bg-purple-900";

    function update() {
        try {
            const checked = Array.from(checkboxes).filter((cb) => cb.checked);
            const count = checked.length;

            // Rebuild pills safely
            pillsBox.innerHTML = "";
            checked.forEach((cb) => {
                const span = document.createElement("span");
                span.className = pillClasses;
                span.textContent =
                    cb.nextElementSibling?.textContent?.trim() || "Unnamed";
                pillsBox.appendChild(span);
            });

            // Warning when > max
            if (count > max) {
                warnBox.textContent = `Selected ${count} prompts. Selecting more than ${max} prompts can degrade agent performance with the server.`;
            } else {
                warnBox.textContent = "";
            }
        } catch (error) {
            console.error("Error updating prompt select:", error);
        }
    }

    if (clearBtn) {
        clearBtn.addEventListener("click", () => {
            checkboxes.forEach((cb) => (cb.checked = false));
            update();
        });
    }

    if (selectBtn) {
        selectBtn.addEventListener("click", () => {
            checkboxes.forEach((cb) => (cb.checked = true));
            update();
        });
    }

    update(); // Initial render
    checkboxes.forEach((cb) => cb.addEventListener("change", update));
}

// ===================================================================
// INACTIVE ITEMS HANDLING
// ===================================================================

function toggleInactiveItems(type) {
    const checkbox = safeGetElement(`show-inactive-${type}`);
    if (!checkbox) {
        return;
    }

    const url = new URL(window.location);
    if (checkbox.checked) {
        url.searchParams.set("include_inactive", "true");
    } else {
        url.searchParams.delete("include_inactive");
    }
    window.location = url;
}

async function handleToggleSubmit(event, type) {
  event.preventDefault();

  const form = event.target;
  const isInactiveCheckedBool = isInactiveChecked(type);

  // The form includes: <input type="hidden" name="activate" value="true|false" />
  const formData = new FormData(form);
  const activateVal = (formData.get("activate") || "").toString().toLowerCase();
  const activate = activateVal === "true" || activateVal === "1" || activateVal === "yes";

  // FastAPI route signature expects activate as QUERY param (not form field)
  const url = new URL(form.action, window.location.origin);
  url.searchParams.set("activate", String(activate));
  url.searchParams.set("is_inactive_checked", String(!!isInactiveCheckedBool));

  try {
    const headers = await rbacHeaders();
    const resp = await fetchWithTimeout(url.toString(), { method: "POST", headers });

    const text = await resp.text();
    let payload = null;
    try {
      payload = text ? JSON.parse(text) : null;
    } catch (_) {
      payload = null;
    }

    if (!resp.ok) {
      const msg =
        (payload && (payload.detail || payload.message)) ||
        text ||
        `Failed: HTTP ${resp.status}`;
      showErrorMessage(msg);
      return false;
    }

    const msg =
      (payload && (payload.message || payload.status)) ||
      `Gateway ${activate ? "activated" : "deactivated"} successfully`;

    showSuccessMessage(msg);
    window.location.reload();
    return false;
  } catch (err) {
    showErrorMessage(err?.message || "Toggle failed");
    return false;
  }
}

async function handleSubmitWithConfirmation(event, type) {
  event.preventDefault();

  const confirmationMessage =
    `Are you sure you want to permanently delete this ${type}? (Deactivation is reversible, deletion is permanent)`;

  if (!confirm(confirmationMessage)) return false;

  const form = event.target;
  const isInactiveCheckedBool = isInactiveChecked(type);

  // Delete uses DELETE /gateways/{gateway_id}
  const url = new URL(form.action, window.location.origin);
  url.searchParams.set("is_inactive_checked", String(!!isInactiveCheckedBool));

  try {
    const headers = await rbacHeaders();
    const resp = await fetchWithTimeout(url.toString(), { method: "DELETE", headers });

    const text = await resp.text();
    let payload = null;
    try {
      payload = text ? JSON.parse(text) : null;
    } catch (_) {
      payload = null;
    }

    if (!resp.ok) {
      const msg =
        (payload && (payload.detail || payload.message)) ||
        text ||
        `Failed: HTTP ${resp.status}`;
      showErrorMessage(msg);
      return false;
    }

    const msg =
      (payload && (payload.message || payload.status)) ||
      "Gateway deleted successfully";

    showSuccessMessage(msg);
    window.location.reload();
    return false;
  } catch (err) {
    showErrorMessage(err?.message || "Delete failed");
    return false;
  }
}


function autoHideToast(successId, errorId) {
  const successEl = document.getElementById(successId);
  const errorEl = document.getElementById(errorId);
  const toastEl = successEl || errorEl;
  if (!toastEl) return;

  window.setTimeout(() => {
    toastEl.style.transition = "opacity 250ms ease";
    toastEl.style.opacity = "0";

    window.setTimeout(() => {
      toastEl.remove();
      try {
        const url = new URL(window.location.href);
        url.searchParams.delete("success");
        url.searchParams.delete("error");
        window.history.replaceState({}, "", url.toString());
      } catch (e) {}
    }, 260);
  }, 8000);
}

document.addEventListener("DOMContentLoaded", () => {
  autoHideToast("tools-toast-success", "tools-toast-error");
  autoHideToast("gateways-toast-success", "gateways-toast-error");
  autoHideToast("servers-toast-success", "servers-toast-error");
});



function showAdminBanner(message, success = true) {
  // Minimal, dependency-free banner.
  // If you already have a toast system, replace this function to hook into it.
  let el = document.getElementById("admin-banner");
  if (!el) {
    el = document.createElement("div");
    el.id = "admin-banner";
    el.className =
      "fixed top-4 right-4 z-50 max-w-sm px-4 py-3 rounded-lg shadow-lg text-sm";
    document.body.appendChild(el);
  }

  el.textContent = message;
  el.classList.remove("bg-green-600", "bg-red-600", "text-white");
  el.classList.add(success ? "bg-green-600" : "bg-red-600", "text-white");

  // Auto hide
  setTimeout(() => {
    if (el) el.remove();
  }, 3500);
}

async function deleteTool(toolId) {
  try {
    console.log(`Deleting tool ID: ${toolId}`);

    // 1) DEBOUNCE (prevent double click)
    const now = Date.now();
    window._deleteState = window._deleteState || {
      lastRequestTime: new Map(),
      activeRequests: new Map(),
      debounceDelay: 1500,
      requestTimeout: 15000,
    };

    const last = window._deleteState.lastRequestTime.get(toolId) || 0;
    const since = now - last;
    if (since < window._deleteState.debounceDelay) {
      const waitTime = Math.ceil(
        (window._deleteState.debounceDelay - since) / 1000
      );
      showErrorMessage(
        `Please wait ${waitTime} more second${waitTime > 1 ? "s" : ""} before trying again.`
      );
      return;
    }

    // 2) CONFIRMATION
    const ok = confirm(
      "Are you sure you want to permanently delete this tool? (Deactivation is reversible, deletion is permanent)"
    );
    if (!ok) return;

    // 3) BUTTON STATE
    const btn = document.querySelector(
      `[data-delete-tool-id="${toolId}"]`
    );
    if (btn) {
      if (btn.disabled) return;
      btn.disabled = true;
      btn.dataset.originalText = btn.textContent;
      btn.textContent = "Deleting...";
      btn.classList.add("opacity-50", "cursor-not-allowed");
    }

    // 4) CANCEL EXISTING REQUEST
    const existing = window._deleteState.activeRequests.get(toolId);
    if (existing) {
      existing.abort();
      window._deleteState.activeRequests.delete(toolId);
    }

    // 5) CREATE CONTROLLER + TIMEOUT
    const controller = new AbortController();
    window._deleteState.activeRequests.set(toolId, controller);
    window._deleteState.lastRequestTime.set(toolId, now);

    const timeoutId = setTimeout(() => {
      controller.abort();
    }, window._deleteState.requestTimeout);

    // IMPORTANT: force SAME ORIGIN + SAME SCHEME as current page
    const url = new URL(`${window.ROOT_PATH}/admin/tools/${toolId}/delete`, window.location.href);
    url.protocol = window.location.protocol;
    url.host = window.location.host;

    // Preserve include_inactive flag like your other handlers
    const isInactiveCheckedBool = isInactiveChecked("tools");
    const body = new URLSearchParams();
    body.set("is_inactive_checked", String(isInactiveCheckedBool));

    // 6) FETCH
    const response = await fetch(url.toString(), {
      method: "POST",
      signal: controller.signal,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "Accept": "application/json, text/plain, */*",
        "Cache-Control": "no-cache",
        Pragma: "no-cache",
        "X-Requested-With": "fetch",
      },
      body: body.toString(),
      credentials: "same-origin",
      redirect: "manual",
    });

    clearTimeout(timeoutId);
    window._deleteState.activeRequests.delete(toolId);

    // 7) HANDLE RESPONSE (JSON OR TEXT)
    const rawText = await response.text();
    let data = null;
    try {
      data = rawText ? JSON.parse(rawText) : null;
    } catch (_e) {
      data = null;
    }

    if (!response.ok) {
      // Status-based errors (like tool test)
      if (response.status === 403) {
        throw new Error(data?.message || data?.detail || "You are not allowed to delete this tool.");
      } else if (response.status === 404) {
        throw new Error(data?.message || data?.detail || "Tool not found. It may have already been deleted.");
      } else if (response.status === 429) {
        throw new Error("Too many requests. Please wait a moment and try again.");
      } else if (response.status >= 500) {
        throw new Error(`Server error (${response.status}). Please try again in a few seconds.`);
      } else {
        // If backend returned HTML/redirect, show snippet
        const location = response.headers.get("location");
        if (location) {
          throw new Error(`Unexpected redirect: ${location}`);
        }
        throw new Error(`HTTP ${response.status}: ${rawText?.slice(0, 200) || response.statusText}`);
      }
    }

    // If backend returns JSON success
    if (data && data.success === true) {
      showSuccessMessage(data.message || "Tool deleted successfully!");
    } else if (data && data.success === false) {
      throw new Error(data.message || "Delete failed.");
    } else {
      // If backend still redirects (non-JSON), treat as success-ish and reload
      showSuccessMessage("Tool deleted. Refreshing…");
    }

    // 8) REFRESH LIKE YOUR OTHER FLOW
    const pageUrl = new URL(window.location.href);
    if (String(isInactiveCheckedBool).toLowerCase() === "true") {
      pageUrl.searchParams.set("include_inactive", "true");
    } else {
      pageUrl.searchParams.delete("include_inactive");
    }
    pageUrl.hash = "tools";
    window.location.href = pageUrl.toString();

  } catch (error) {
    console.error("Error deleting tool:", error);

    // Tool-test style network error mapping
    let msg = error.message;

    if (error.name === "AbortError") {
      msg = "Request was cancelled or timed out. Please try again.";
    } else if (
      msg.includes("Failed to fetch") ||
      msg.includes("NetworkError")
    ) {
      msg = "Unable to connect to the server. Please wait a moment and try again.";
    } else if (
      msg.includes("empty response") ||
      msg.includes("ERR_EMPTY_RESPONSE")
    ) {
      msg = "The server returned an empty response. Please wait a moment and try again.";
    }

    showErrorMessage(msg);
  } finally {
    // ALWAYS RESTORE BUTTON STATE
    const btn = document.querySelector(
      `[data-delete-tool-id="${toolId}"]`
    );
    if (btn) {
      btn.disabled = false;
      btn.textContent = btn.dataset.originalText || "Delete";
      btn.classList.remove("opacity-50", "cursor-not-allowed");
    }
  }
}





// ===================================================================
// ENHANCED TOOL TESTING with Safe State Management
// ===================================================================

// Track active tool test requests globally
const toolTestState = {
    activeRequests: new Map(), // toolId -> AbortController
    lastRequestTime: new Map(), // toolId -> timestamp
    debounceDelay: 1000, // Increased from 500ms
    requestTimeout: window.MCPGATEWAY_UI_TOOL_TEST_TIMEOUT || 60000, // Use configurable timeout
};

let toolInputSchemaRegistry = null;

/**
 * ENHANCED: Tool testing with improved race condition handling
 */
async function testTool(toolId) {
    try {
        console.log(`Testing tool ID: ${toolId}`);

        // 1. ENHANCED DEBOUNCING: More aggressive to prevent rapid clicking
        const now = Date.now();
        const lastRequest = toolTestState.lastRequestTime.get(toolId) || 0;
        const timeSinceLastRequest = now - lastRequest;
        const enhancedDebounceDelay = 2000; // Increased from 1000ms

        if (timeSinceLastRequest < enhancedDebounceDelay) {
            console.log(
                `Tool ${toolId} test request debounced (${timeSinceLastRequest}ms ago)`,
            );
            const waitTime = Math.ceil(
                (enhancedDebounceDelay - timeSinceLastRequest) / 1000,
            );
            showErrorMessage(
                `Please wait ${waitTime} more second${waitTime > 1 ? "s" : ""} before testing again`,
            );
            return;
        }

        // 2. MODAL PROTECTION: Enhanced check
        if (AppState.isModalActive("tool-test-modal")) {
            console.warn("Tool test modal is already active");
            return; // Silent fail for better UX
        }

        // 3. BUTTON STATE: Immediate feedback with better state management
        const testButton = document.querySelector(
            `[onclick*="testTool('${toolId}')"]`,
        );
        if (testButton) {
            if (testButton.disabled) {
                console.log(
                    "Test button already disabled, request in progress",
                );
                return;
            }
            testButton.disabled = true;
            testButton.textContent = "Testing...";
            testButton.classList.add("opacity-50", "cursor-not-allowed");
        }

        // 4. REQUEST CANCELLATION: Enhanced cleanup
        const existingController = toolTestState.activeRequests.get(toolId);
        if (existingController) {
            console.log(`Cancelling existing request for tool ${toolId}`);
            existingController.abort();
            toolTestState.activeRequests.delete(toolId);
        }

        // 5. CREATE NEW REQUEST with longer timeout
        const controller = new AbortController();
        toolTestState.activeRequests.set(toolId, controller);
        toolTestState.lastRequestTime.set(toolId, now);

        // 6. MAKE REQUEST with increased timeout
        const response = await fetchWithTimeout(
        `${window.ROOT_PATH}/tool-testing/tools/${toolId}`,
        {
            signal: controller.signal,
            headers: {
            "Cache-Control": "no-cache",
            Pragma: "no-cache",
            },
            credentials: "include",
        },
        toolTestState.requestTimeout,
        );


        if (!response.ok) {
            if (response.status === 404) {
                throw new Error(
                    `Tool with ID ${toolId} not found. It may have been deleted.`,
                );
            } else if (response.status === 429) {
                throw new Error(
                    "Too many requests. Please wait a moment before testing again.",
                );
            } else if (response.status >= 500) {
                throw new Error(
                    `Server error (${response.status}). The server may be overloaded. Please try again in a few seconds.`,
                );
            } else {
                throw new Error(
                    `HTTP ${response.status}: ${response.statusText}`,
                );
            }
        }

        const tool = await response.json();
        console.log(`Tool ${toolId} fetched successfully`, tool);
        toolInputSchemaRegistry = tool;

        // 7. CLEAN STATE before proceeding
        toolTestState.activeRequests.delete(toolId);

        // Store in safe state
        AppState.currentTestTool = tool;

        // Set modal title and description safely - NO DOUBLE ESCAPING
        const titleElement = safeGetElement("tool-test-modal-title");
        const descElement = safeGetElement("tool-test-modal-description");

        if (titleElement) {
            titleElement.textContent = "Test Tool: " + (tool.name || "Unknown");
        }
        if (descElement) {
            if (tool.description) {
                // Escape HTML and then replace newlines with <br/> tags
                descElement.innerHTML = escapeHtml(tool.description).replace(
                    /\n/g,
                    "<br/>",
                );
            } else {
                descElement.textContent = "No description available.";
            }
        }

        const container = safeGetElement("tool-test-form-fields");
        if (!container) {
            console.error("Tool test form fields container not found");
            return;
        }

        container.innerHTML = ""; // Clear previous fields

        // Parse the input schema safely
        let schema = tool.inputSchema;
        if (typeof schema === "string") {
            try {
                schema = JSON.parse(schema);
            } catch (e) {
                console.error("Invalid JSON schema", e);
                schema = {};
            }
        }

        // Dynamically create form fields based on schema.properties
        if (schema && schema.properties) {
            for (const key in schema.properties) {
                const prop = schema.properties[key];

                // Validate the property name
                const keyValidation = validateInputName(key, "schema property");
                if (!keyValidation.valid) {
                    console.warn(`Skipping invalid schema property: ${key}`);
                    continue;
                }

                const fieldDiv = document.createElement("div");
                fieldDiv.className =
                    "rounded-lg border border-gray-200 dark:border-gray-700 p-3 bg-white dark:bg-gray-900/40";

                // Field label - use textContent to avoid double escaping
                const label = document.createElement("label");
                label.className =
                    "block text-sm font-medium text-gray-700 dark:text-white";

                // Create span for label text
                const labelText = document.createElement("span");
                labelText.textContent = keyValidation.value;
                label.appendChild(labelText);

                // Add red star if field is required
                if (schema.required && schema.required.includes(key)) {
                    const requiredMark = document.createElement("span");
                    requiredMark.textContent = " *";
                    requiredMark.className = "text-red-500";
                    label.appendChild(requiredMark);
                }

                fieldDiv.appendChild(label);

                // Description help text - use textContent
                if (prop.description) {
                    const description = document.createElement("small");
                    description.textContent = prop.description;
                    description.className = "text-gray-500 block mb-1";
                    fieldDiv.appendChild(description);
                }

                if (prop.type === "array") {
                    const arrayContainer = document.createElement("div");
                    arrayContainer.className = "space-y-2";

                    function createArrayInput(value = "") {
                        const wrapper = document.createElement("div");
                        wrapper.className = "flex items-center space-x-2";

                        const input = document.createElement("input");
                        input.name = keyValidation.value;
                        input.required =
                            schema.required && schema.required.includes(key);
                        input.className =
                            "mt-1 block w-full rounded-md border border-gray-300 dark:border-gray-400 shadow-sm focus:figma-blue-border focus:ring-indigo-500 bg-white dark:bg-white text-gray-900 dark:text-gray-900";

                        const itemTypes = Array.isArray(prop.items?.anyOf)
                            ? prop.items.anyOf.map((t) => t.type)
                            : [prop.items?.type];

                        if (
                            itemTypes.includes("number") ||
                            itemTypes.includes("integer")
                        ) {
                            input.type = "number";
                            input.step = itemTypes.includes("integer")
                                ? "1"
                                : "any";
                        } else if (itemTypes.includes("boolean")) {
                            input.type = "checkbox";
                            input.value = "true";
                            input.checked = value === true || value === "true";
                        } else {
                            input.type = "text";
                        }

                        if (
                            typeof value === "string" ||
                            typeof value === "number"
                        ) {
                            input.value = value;
                        }

                        const delBtn = document.createElement("button");
                        delBtn.type = "button";
                        delBtn.className =
                            "ml-2 text-red-600 hover:text-red-800 focus:outline-none";
                        delBtn.title = "Delete";
                        delBtn.textContent = "×";
                        delBtn.addEventListener("click", () => {
                            arrayContainer.removeChild(wrapper);
                        });

                        wrapper.appendChild(input);

                        if (itemTypes.includes("boolean")) {
                            const hidden = document.createElement("input");
                            hidden.type = "hidden";
                            hidden.name = keyValidation.value;
                            hidden.value = "false";
                            wrapper.appendChild(hidden);
                        }

                        wrapper.appendChild(delBtn);
                        return wrapper;
                    }

                    const addBtn = document.createElement("button");
                    addBtn.type = "button";
                    addBtn.className =
                        "mt-2 px-2 py-1 bg-indigo-500 text-white rounded hover:bg-indigo-600 focus:outline-none";
                    addBtn.textContent = "Add items";
                    addBtn.addEventListener("click", () => {
                        arrayContainer.appendChild(createArrayInput());
                    });

                    if (Array.isArray(prop.default)) {
                        if (prop.default.length > 0) {
                            prop.default.forEach((val) => {
                                arrayContainer.appendChild(
                                    createArrayInput(val),
                                );
                            });
                        } else {
                            // Create one empty input for empty default arrays
                            arrayContainer.appendChild(createArrayInput());
                        }
                    } else {
                        arrayContainer.appendChild(createArrayInput());
                    }

                    fieldDiv.appendChild(arrayContainer);
                    fieldDiv.appendChild(addBtn);
                } else {
                    // Input field with validation (with multiline support)
                    let fieldInput;
                    const isTextType = prop.type === "text";
                    if (isTextType) {
                        fieldInput = document.createElement("textarea");
                        fieldInput.rows = 4;
                    } else {
                        fieldInput = document.createElement("input");
                        if (prop.type === "number" || prop.type === "integer") {
                            fieldInput.type = "number";
                        } else if (prop.type === "boolean") {
                            fieldInput.type = "checkbox";
                            fieldInput.value = "true";
                        } else {
                            fieldInput = document.createElement("textarea");
                            fieldInput.rows = 1;
                        }
                    }

                    fieldInput.name = keyValidation.value;
                    fieldInput.required =
                        schema.required && schema.required.includes(key);
                    fieldInput.className =
                        prop.type === "boolean"
                            ? "mt-1 h-4 w-4 figma-blue-txt dark:text-indigo-200 border border-gray-300 rounded"
                            : "mt-1 block w-full rounded-md border border-gray-300 dark:border-gray-400 shadow-sm focus:figma-blue-border focus:ring-indigo-500 bg-white dark:bg-white text-gray-900 dark:text-gray-900";

                    // Set default values here
                    if (prop.default !== undefined) {
                        if (fieldInput.type === "checkbox") {
                            fieldInput.checked = prop.default === true;
                        } else if (isTextType) {
                            fieldInput.value = prop.default;
                        } else {
                            fieldInput.value = prop.default;
                        }
                    }

                    fieldDiv.appendChild(fieldInput);
                    if (prop.default !== undefined) {
                        if (fieldInput.type === "checkbox") {
                            const hiddenInput = document.createElement("input");
                            hiddenInput.type = "hidden";
                            hiddenInput.value = "false";
                            hiddenInput.name = keyValidation.value;
                            fieldDiv.appendChild(hiddenInput);
                        }
                    }
                }

                container.appendChild(fieldDiv);
            }
        }

        openModal("tool-test-modal");
        console.log("✓ Tool test modal loaded successfully");
    } catch (error) {
        console.error("Error fetching tool details for testing:", error);

        // Clean up state on error
        toolTestState.activeRequests.delete(toolId);

        let errorMessage = error.message;

        // Enhanced error handling for rapid clicking scenarios
        if (error.name === "AbortError") {
            errorMessage = "Request was cancelled. Please try again.";
        } else if (
            error.message.includes("Failed to fetch") ||
            error.message.includes("NetworkError")
        ) {
            errorMessage =
                "Unable to connect to the server. Please wait a moment and try again.";
        } else if (
            error.message.includes("empty response") ||
            error.message.includes("ERR_EMPTY_RESPONSE")
        ) {
            errorMessage =
                "The server returned an empty response. Please wait a moment and try again.";
        } else if (error.message.includes("timeout")) {
            errorMessage =
                "Request timed out. Please try again in a few seconds.";
        }

        showErrorMessage(errorMessage);
    } finally {
        // 8. ALWAYS RESTORE BUTTON STATE
        const testButton = document.querySelector(
            `[onclick*="testTool('${toolId}')"]`,
        );
        if (testButton) {
            testButton.disabled = false;
            testButton.textContent = "Test";
            testButton.classList.remove("opacity-50", "cursor-not-allowed");
        }
    }
}

async function runToolTest() {
  const form = safeGetElement("tool-test-form");
  const loadingElement = safeGetElement("tool-test-loading");
  const resultContainer = safeGetElement("tool-test-result");
  const runButton = document.querySelector('button[onclick="runToolTest()"]');

  if (!form || !AppState.currentTestTool) {
    console.error("Tool test form or current tool not found");
    showErrorMessage("Tool test form not available");
    return;
  }

  // Prevent multiple concurrent test runs
  if (runButton && runButton.disabled) {
    console.log("Tool test already running");
    return;
  }

  // Small helper to render results consistently (CodeMirror if available)
  function renderToolTestResult(resultStr) {
    if (!resultContainer) return;

    resultContainer.innerHTML = "";

    if (window.CodeMirror) {
      try {
        AppState.toolTestResultEditor = window.CodeMirror(resultContainer, {
          value: resultStr,
          mode: "application/json",
          theme: "monokai",
          readOnly: true,
          lineNumbers: true,
        });
        return;
      } catch (editorError) {
        console.error("Error creating CodeMirror editor:", editorError);
      }
    }

    const pre = document.createElement("pre");
    pre.className =
      "bg-gray-100 p-4 rounded overflow-auto max-h-96 dark:bg-gray-800 dark:text-gray-100";
    pre.textContent = resultStr;
    resultContainer.appendChild(pre);
  }

  try {
    // Disable run button
    if (runButton) {
      runButton.disabled = true;
      runButton.textContent = "Running...";
      runButton.classList.add("opacity-50");
    }

    // Show loading
    if (loadingElement) loadingElement.style.display = "block";
    if (resultContainer) resultContainer.innerHTML = "";

    const formData = new FormData(form);
    const params = {};

    // Prefer the tool schema we fetched in testTool()
    const schema = toolInputSchemaRegistry?.inputSchema;

    if (schema && schema.properties) {
      for (const key in schema.properties) {
        const prop = schema.properties[key];
        const keyValidation = validateInputName(key, "parameter");
        if (!keyValidation.valid) {
          console.warn(`Skipping invalid parameter: ${key}`);
          continue;
        }

        let value;

        if (prop.type === "array") {
          const inputValues = formData.getAll(key);

          try {
            // Convert values based on items schema type
            if (prop.items) {
              const itemType = Array.isArray(prop.items.anyOf)
                ? prop.items.anyOf.map((t) => t.type)
                : [prop.items.type];

              if (itemType.includes("number") || itemType.includes("integer")) {
                value = inputValues.map((v) => {
                  const num = Number(v);
                  if (isNaN(num)) throw new Error(`Invalid number: ${v}`);
                  return num;
                });
              } else if (itemType.includes("boolean")) {
                value = inputValues.map((v) => v === "true" || v === true);
              } else if (itemType.includes("object")) {
                value = inputValues.map((v) => {
                  try {
                    const parsed = JSON.parse(v);
                    if (typeof parsed !== "object" || Array.isArray(parsed)) {
                      throw new Error("Value must be an object");
                    }
                    return parsed;
                  } catch {
                    throw new Error(`Invalid object format for ${key}`);
                  }
                });
              } else {
                value = inputValues;
              }
            } else {
              value = inputValues;
            }

            // Handle empty values
            if (value.length === 0 || (value.length === 1 && value[0] === "")) {
              if (schema.required && schema.required.includes(key)) {
                params[keyValidation.value] = [];
              }
              continue;
            }

            params[keyValidation.value] = value;
          } catch (error) {
            console.error(`Error parsing array values for ${key}:`, error);
            showErrorMessage(
              `Invalid input format for ${key}. Please check the values are in correct format.`,
            );
            throw error;
          }
        } else {
          value = formData.get(key);

          if (value === null || value === undefined || value === "") {
            if (schema.required && schema.required.includes(key)) {
              params[keyValidation.value] = "";
            }
            continue;
          }

          if (prop.type === "number" || prop.type === "integer") {
            params[keyValidation.value] = Number(value);
          } else if (prop.type === "boolean") {
            params[keyValidation.value] = value === "true" || value === true;
          } else if (prop.enum) {
            if (prop.enum.includes(value)) params[keyValidation.value] = value;
          } else {
            params[keyValidation.value] = value;
          }
        }
      }
    }

    // Execute tool test
    const response = await fetchWithTimeout(
      `${window.ROOT_PATH}/tool-testing/tools/${AppState.currentTestTool.id}/run`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ params }), // ONLY logical params
      },
      window.MCPGATEWAY_UI_TOOL_TEST_TIMEOUT || 60000,
    );

    // Read raw text first so we can show meaningful errors even if not JSON
    const rawText = await response.text();

    let data = null;
    try {
      data = rawText ? JSON.parse(rawText) : null;
    } catch (e) {
      data = null;
    }

    // Permission / auth / server errors should be visible in UI
    if (!response.ok) {
      let backendMsg =
        (data && (data.detail || data.message || data.error)) ||
        rawText ||
        `HTTP ${response.status}: ${response.statusText}`;

      if (response.status === 401) backendMsg = "Not authenticated. Please login again.";
      if (response.status === 403) backendMsg = `Permission denied: ${backendMsg}`;

      const errorPayload = {
        ok: false,
        status: response.status,
        error: backendMsg,
        // optionally keep raw body for debugging:
        // raw: rawText,
      };

      renderToolTestResult(JSON.stringify(errorPayload, null, 2));
      console.warn("Tool test denied/failed:", errorPayload);
      return;
    }

    // ✅ Success payload: support both (rpc_request/rpc_response) and direct JSON-RPC response shapes
    const rpcRequest =
      data?.rpc_request ?? {
        jsonrpc: "2.0",
        id: Date.now(),
        method: AppState.currentTestTool.name,
        params,
      };

    const rpcResponse = data?.rpc_response ?? data;

    const resultStr = JSON.stringify(
      {
        request: rpcRequest,
        response: rpcResponse,
      },
      null,
      2,
    );

    renderToolTestResult(resultStr);

    console.log("✓ Tool test completed successfully");
  } catch (error) {
    console.error("Tool test error:", error);

    // Make fetch errors visible in the result panel too
    const errorMessage = handleFetchError(error, "run tool test");
    const errorPayload = {
      ok: false,
      error: errorMessage,
    };

    // Render in the result panel (preferred)
    const resultStr = JSON.stringify(errorPayload, null, 2);
    if (resultContainer) {
      // use helper if it exists inside scope
      try {
        // if helper exists above, it will render CodeMirror or fallback
        const pre = document.createElement("pre");
        pre.className = "text-red-600 p-4 whitespace-pre-wrap";
        pre.textContent = resultStr;
        resultContainer.innerHTML = "";
        resultContainer.appendChild(pre);
      } catch (e) {
        // last resort
        showErrorMessage(errorMessage);
      }
    } else {
      showErrorMessage(errorMessage);
    }
  } finally {
    // Always restore UI state
    if (loadingElement) loadingElement.style.display = "none";
    if (runButton) {
      runButton.disabled = false;
      runButton.textContent = "Run Tool";
      runButton.classList.remove("opacity-50");
    }
  }
}


function renderToolTestResult(resultStr, resultContainer) {
  if (!resultContainer) return;

  resultContainer.innerHTML = "";

  if (window.CodeMirror) {
    try {
      AppState.toolTestResultEditor = window.CodeMirror(resultContainer, {
        value: resultStr,
        mode: "application/json",
        theme: "monokai",
        readOnly: true,
        lineNumbers: true,
      });
      return;
    } catch (e) {
      console.error("CodeMirror render failed, falling back:", e);
    }
  }

  const pre = document.createElement("pre");
  pre.className =
    "bg-gray-100 p-4 rounded overflow-auto max-h-96 dark:bg-gray-800 dark:text-gray-100";
  pre.textContent = resultStr;
  resultContainer.appendChild(pre);
}

/**
 * NEW: Cleanup function for tool test state
 */
function cleanupToolTestState() {
    // Cancel all active requests
    for (const [toolId, controller] of toolTestState.activeRequests) {
        try {
            controller.abort();
            console.log(`Cancelled request for tool ${toolId}`);
        } catch (error) {
            console.warn(`Error cancelling request for tool ${toolId}:`, error);
        }
    }

    // Clear all state
    toolTestState.activeRequests.clear();
    toolTestState.lastRequestTime.clear();

    console.log("✓ Tool test state cleaned up");
}

/**
 * NEW: Tool test modal specific cleanup
 */
function cleanupToolTestModal() {
    try {
        // Clear current test tool
        AppState.currentTestTool = null;

        // Clear result editor
        if (AppState.toolTestResultEditor) {
            try {
                AppState.toolTestResultEditor.toTextArea();
                AppState.toolTestResultEditor = null;
            } catch (error) {
                console.warn(
                    "Error cleaning up tool test result editor:",
                    error,
                );
            }
        }

        // Reset form
        const form = safeGetElement("tool-test-form");
        if (form) {
            form.reset();
        }

        // Clear result container
        const resultContainer = safeGetElement("tool-test-result");
        if (resultContainer) {
            resultContainer.innerHTML = "";
        }

        // Hide loading
        const loadingElement = safeGetElement("tool-test-loading");
        if (loadingElement) {
            loadingElement.style.display = "none";
        }

        console.log("✓ Tool test modal cleaned up");
    } catch (error) {
        console.error("Error cleaning up tool test modal:", error);
    }
}

// ===================================================================
// PROMPT TEST FUNCTIONALITY
// ===================================================================

// State management for prompt testing
const promptTestState = {
    lastRequestTime: new Map(),
    activeRequests: new Set(),
    currentTestPrompt: null,
};

/**
 * Test a prompt by opening the prompt test modal
 */
async function testPrompt(promptName) {
    try {
        console.log(`Testing prompt: ${promptName}`);

        // Debouncing to prevent rapid clicking
        const now = Date.now();
        const lastRequest =
            promptTestState.lastRequestTime.get(promptName) || 0;
        const timeSinceLastRequest = now - lastRequest;
        const debounceDelay = 1000;

        if (timeSinceLastRequest < debounceDelay) {
            console.log(`Prompt ${promptName} test request debounced`);
            return;
        }

        // Check if modal is already active
        if (AppState.isModalActive("prompt-test-modal")) {
            console.warn("Prompt test modal is already active");
            return;
        }

        // Update button state
        const testButton = document.querySelector(
            `[onclick*="testPrompt('${promptName}')"]`,
        );
        if (testButton) {
            if (testButton.disabled) {
                console.log(
                    "Test button already disabled, request in progress",
                );
                return;
            }
            testButton.disabled = true;
            testButton.textContent = "Loading...";
            testButton.classList.add("opacity-50", "cursor-not-allowed");
        }

        // Record request time and mark as active
        promptTestState.lastRequestTime.set(promptName, now);
        promptTestState.activeRequests.add(promptName);

        // Fetch prompt details
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000);

        try {
            // Fetch prompt details from the prompts endpoint (view mode)
            const response = await fetch(
                `${window.ROOT_PATH}/admin/prompts/${encodeURIComponent(promptName)}`,
                {
                    method: "GET",
                    headers: {
                        Accept: "application/json",
                    },
                    credentials: "include",
                    signal: controller.signal,
                },
            );

            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(
                    `Failed to fetch prompt details: ${response.status} ${response.statusText}`,
                );
            }

            const prompt = await response.json();
            promptTestState.currentTestPrompt = prompt;

            // Set modal title and description
            const titleElement = safeGetElement("prompt-test-modal-title");
            const descElement = safeGetElement("prompt-test-modal-description");

            if (titleElement) {
                titleElement.textContent = `Test Prompt: ${prompt.name || promptName}`;
            }
            if (descElement) {
                if (prompt.description) {
                    // Escape HTML and then replace newlines with <br/> tags
                    descElement.innerHTML = escapeHtml(
                        prompt.description,
                    ).replace(/\n/g, "<br/>");
                } else {
                    descElement.textContent = "No description available.";
                }
            }

            // Build form fields based on prompt arguments
            buildPromptTestForm(prompt);

            // Open the modal
            openModal("prompt-test-modal");
        } catch (error) {
            clearTimeout(timeoutId);

            if (error.name === "AbortError") {
                console.warn("Request was cancelled (timeout or user action)");
                showErrorMessage("Request timed out. Please try again.");
            } else {
                console.error("Error fetching prompt details:", error);
                const errorMessage =
                    error.message || "Failed to load prompt details";
                showErrorMessage(`Error testing prompt: ${errorMessage}`);
            }
        }
    } catch (error) {
        console.error("Error in testPrompt:", error);
        showErrorMessage(`Error testing prompt: ${error.message}`);
    } finally {
        // Always restore button state
        const testButton = document.querySelector(
            `[onclick*="testPrompt('${promptName}')"]`,
        );
        if (testButton) {
            testButton.disabled = false;
            testButton.textContent = "Test";
            testButton.classList.remove("opacity-50", "cursor-not-allowed");
        }

        // Clean up state
        promptTestState.activeRequests.delete(promptName);
    }
}

/**
 * Build the form fields for prompt testing based on prompt arguments
 */
function buildPromptTestForm(prompt) {
    const fieldsContainer = safeGetElement("prompt-test-form-fields");
    if (!fieldsContainer) {
        console.error("Prompt test form fields container not found");
        return;
    }

    // Clear existing fields
    fieldsContainer.innerHTML = "";

    if (!prompt.arguments || prompt.arguments.length === 0) {
        fieldsContainer.innerHTML = `
            <div class="text-gray-500 dark:text-gray-400 text-sm italic">
                This prompt has no arguments - it will render as-is.
            </div>
        `;
        return;
    }

    // Create fields for each prompt argument
    prompt.arguments.forEach((arg, index) => {
        const fieldDiv = document.createElement("div");
        fieldDiv.className = "space-y-2";

        const label = document.createElement("label");
        label.className =
            "block text-sm font-medium text-gray-700 dark:text-gray-300";
        label.textContent = `${arg.name}${arg.required ? " *" : ""}`;

        const input = document.createElement("input");
        input.type = "text";
        input.id = `prompt-arg-${index}`;
        input.name = `arg-${arg.name}`;
        input.className =
            "mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:figma-blue-border focus:ring-indigo-500 dark:bg-gray-700 dark:border-gray-600 dark:text-gray-300";

        if (arg.description) {
            input.placeholder = arg.description;
        }

        if (arg.required) {
            input.required = true;
        }

        fieldDiv.appendChild(label);
        if (arg.description) {
            const description = document.createElement("div");
            description.className = "text-xs text-gray-500 dark:text-gray-400";
            description.textContent = arg.description;
            fieldDiv.appendChild(description);
        }
        fieldDiv.appendChild(input);

        fieldsContainer.appendChild(fieldDiv);
    });
}

/**
 * Run the prompt test by calling the API with the provided arguments
 */
async function runPromptTest() {
    const form = safeGetElement("prompt-test-form");
    const loadingElement = safeGetElement("prompt-test-loading");
    const resultContainer = safeGetElement("prompt-test-result");
    const runButton = document.querySelector(
        'button[onclick="runPromptTest()"]',
    );

    if (!form || !promptTestState.currentTestPrompt) {
        console.error("Prompt test form or current prompt not found");
        showErrorMessage("Prompt test form not available");
        return;
    }

    // Prevent multiple concurrent test runs
    if (runButton && runButton.disabled) {
        console.log("Prompt test already running");
        return;
    }

    try {
        // Disable button and show loading
        if (runButton) {
            runButton.disabled = true;
            runButton.textContent = "Rendering...";
        }
        if (loadingElement) {
            loadingElement.classList.remove("hidden");
        }
        if (resultContainer) {
            resultContainer.innerHTML = `
                <div class="text-gray-500 dark:text-gray-400 text-sm italic">
                    Rendering prompt...
                </div>
            `;
        }

        // Collect form data (prompt arguments)
        const formData = new FormData(form);
        const args = {};

        // Parse the form data into arguments object
        for (const [key, value] of formData.entries()) {
            if (key.startsWith("arg-")) {
                const argName = key.substring(4); // Remove 'arg-' prefix
                args[argName] = value;
            }
        }

        // Call the prompt API endpoint
        const response = await fetch(
            `${window.ROOT_PATH}/prompts/${encodeURIComponent(promptTestState.currentTestPrompt.name)}`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                credentials: "include",
                body: JSON.stringify(args),
            },
        );

        if (!response.ok) {
            let errorMessage;
            try {
                const errorData = await response.json();
                errorMessage =
                    errorData.message ||
                    `HTTP ${response.status}: ${response.statusText}`;

                // Show more detailed error information
                if (errorData.details) {
                    errorMessage += `\nDetails: ${errorData.details}`;
                }
            } catch {
                errorMessage = `HTTP ${response.status}: ${response.statusText}`;
            }
            throw new Error(errorMessage);
        }

        const result = await response.json();

        // Display the result
        if (resultContainer) {
            let resultHtml = "";

            if (result.messages && Array.isArray(result.messages)) {
                result.messages.forEach((message, index) => {
                    resultHtml += `
                        <div class="mb-4 p-3 bg-white dark:bg-gray-700 rounded border">
                            <div class="text-sm font-medium text-gray-600 dark:text-gray-300 mb-2">
                                Message ${index + 1} (${message.role || "unknown"})
                            </div>
                            <div class="text-gray-900 dark:text-gray-100 whitespace-pre-wrap">${escapeHtml(message.content?.text || JSON.stringify(message.content) || "")}</div>
                        </div>
                    `;
                });
            } else {
                resultHtml = `
                    <div class="text-gray-900 dark:text-gray-100 whitespace-pre-wrap">${escapeHtml(JSON.stringify(result, null, 2))}</div>
                `;
            }

            resultContainer.innerHTML = resultHtml;
        }

        console.log("Prompt rendered successfully");
    } catch (error) {
        console.error("Error rendering prompt:", error);

        if (resultContainer) {
            resultContainer.innerHTML = `
                <div class="text-red-600 dark:text-red-400 text-sm">
                    <strong>Error:</strong> ${escapeHtml(error.message)}
                </div>
            `;
        }

        showErrorMessage(`Failed to render prompt: ${error.message}`);
    } finally {
        // Hide loading and restore button
        if (loadingElement) {
            loadingElement.classList.add("hidden");
        }
        if (runButton) {
            runButton.disabled = false;
            runButton.textContent = "Render Prompt";
        }
    }
}

/**
 * Clean up prompt test modal state
 */
function cleanupPromptTestModal() {
    try {
        // Clear current test prompt
        promptTestState.currentTestPrompt = null;

        // Reset form
        const form = safeGetElement("prompt-test-form");
        if (form) {
            form.reset();
        }

        // Clear form fields
        const fieldsContainer = safeGetElement("prompt-test-form-fields");
        if (fieldsContainer) {
            fieldsContainer.innerHTML = "";
        }

        // Clear result container
        const resultContainer = safeGetElement("prompt-test-result");
        if (resultContainer) {
            resultContainer.innerHTML = `
                <div class="text-gray-500 dark:text-gray-400 text-sm italic">
                    Click "Render Prompt" to see the rendered output
                </div>
            `;
        }

        // Hide loading
        const loadingElement = safeGetElement("prompt-test-loading");
        if (loadingElement) {
            loadingElement.classList.add("hidden");
        }

        console.log("✓ Prompt test modal cleaned up");
    } catch (error) {
        console.error("Error cleaning up prompt test modal:", error);
    }
}

// ===================================================================
// ENHANCED GATEWAY TEST FUNCTIONALITY
// ===================================================================
/* ---------- Modal state ---------- */
let gatewayBulkTestGatewayId = null;
let gatewayBulkTestInspectCache = null;

let gatewayBulkTestReloadHandler = null;
let gatewayBulkTestRunSelectedHandler = null;
let gatewayBulkTestRunAllHandler = null;
let gatewayBulkTestCloseHandler = null;

/* ---------- Public entry: call from button onclick ---------- */
async function openGatewayToolTesting(gatewayId) {
  try {
    cleanupGatewayBulkTestModal();

    gatewayBulkTestGatewayId = gatewayId;
    gatewayBulkTestInspectCache = null;

    openModal("gateway-bulk-test-modal");

    const reloadBtn = safeGetElement("gateway-bulk-test-reload");
    const runSelectedBtn = safeGetElement("gateway-bulk-test-run-selected");
    const runAllBtn = safeGetElement("gateway-bulk-test-run-all");
    const closeBtn = safeGetElement("gateway-bulk-test-close");

    if (reloadBtn) {
      gatewayBulkTestReloadHandler = async () => await loadGatewayInspection();
      reloadBtn.addEventListener("click", gatewayBulkTestReloadHandler);
    }

    if (runSelectedBtn) {
      gatewayBulkTestRunSelectedHandler = async () => await runBulkTests("selected");
      runSelectedBtn.addEventListener("click", gatewayBulkTestRunSelectedHandler);
    }

    if (runAllBtn) {
      gatewayBulkTestRunAllHandler = async () => await runBulkTests("all");
      runAllBtn.addEventListener("click", gatewayBulkTestRunAllHandler);
    }

    if (closeBtn) {
      gatewayBulkTestCloseHandler = () => handleGatewayBulkTestClose();
      closeBtn.addEventListener("click", gatewayBulkTestCloseHandler);
    }

    await loadGatewayInspection();
  } catch (error) {
    console.error("Error opening gateway tool testing modal:", error);
    if (typeof showErrorMessage === "function") showErrorMessage("Failed to open gateway tool testing modal");
  }
}

/* ---------- Inspect loader ---------- */
async function loadGatewayInspection() {
  const loading = safeGetElement("gateway-bulk-test-loading");
  const toolsDiv = safeGetElement("gateway-bulk-test-tools");
  const errorDiv = safeGetElement("gateway-bulk-test-error");
  const summaryDiv = safeGetElement("gateway-bulk-test-summary");
  const resultsDiv = safeGetElement("gateway-bulk-test-results");
  const resultsList = safeGetElement("gateway-bulk-test-results-list");

  try {
    if (loading) loading.classList.remove("hidden");
    if (errorDiv) {
      errorDiv.classList.add("hidden");
      errorDiv.innerHTML = "";
    }
    if (resultsDiv) resultsDiv.classList.add("hidden");
    if (resultsList) resultsList.innerHTML = "";
    if (toolsDiv) toolsDiv.innerHTML = "";

    const url = `${window.ROOT_PATH}/gateway-testing/gateways/${gatewayBulkTestGatewayId}/inspect`;

    const response = await fetchWithTimeout(url, {
      method: "GET",
      headers: { Accept: "application/json" },
    });

    if (!response.ok) {
      const txt = await response.text();
      throw new Error(`Inspect failed (${response.status}): ${txt}`);
    }

    const data = await response.json();
    gatewayBulkTestInspectCache = data;

    // Summary (matches your blue info box vibe)
    if (summaryDiv) summaryDiv.classList.remove("hidden");

    const gwName = safeGetElement("gateway-bulk-test-gateway-name");
    const gwId = safeGetElement("gateway-bulk-test-gateway-id");
    const toolCount = safeGetElement("gateway-bulk-test-tool-count");
    const promptCount = safeGetElement("gateway-bulk-test-prompt-count");
    const resourceCount = safeGetElement("gateway-bulk-test-resource-count");

    if (gwName) gwName.textContent = (data.gateway && (data.gateway.name || data.gateway.id)) || "";
    if (gwId) gwId.textContent = (data.gateway && data.gateway.id) || "";
    if (toolCount) toolCount.textContent = (data.tools || []).length;
    if (promptCount) promptCount.textContent = (data.prompts || []).length;
    if (resourceCount) resourceCount.textContent = (data.resources || []).length;

    renderGatewayToolsForTesting(data.tools || []);
  } catch (error) {
    console.error("Gateway inspection error:", error);
    if (errorDiv) {
      errorDiv.classList.remove("hidden");
      errorDiv.innerHTML = `
        <div class="rounded-md border border-red-200 bg-red-50 text-red-800 p-3 text-sm dark:border-red-800 dark:bg-red-900/20 dark:text-red-200">
          ❌ ${escapeHtml(error.message || String(error))}
        </div>
      `;
    }
  } finally {
    if (loading) loading.classList.add("hidden");
  }
}

/* ---------- Render tools list (styled like Create MCP Server card) ---------- */
function normalizeInputSchema(tool) {
  // Accepts object OR JSON string OR null
  const raw = tool?.input_schema ?? tool?.inputSchema ?? tool?.inputSchemaJson ?? null;

  if (!raw) return { properties: {}, required: [] };

  // If already an object
  if (typeof raw === "object") {
    return {
      properties: raw.properties && typeof raw.properties === "object" ? raw.properties : {},
      required: Array.isArray(raw.required) ? raw.required : [],
    };
  }

  // If JSON string
  if (typeof raw === "string") {
    try {
      const parsed = JSON.parse(raw);
      return {
        properties: parsed?.properties && typeof parsed.properties === "object" ? parsed.properties : {},
        required: Array.isArray(parsed?.required) ? parsed.required : [],
      };
    } catch (e) {
      console.warn("Invalid input_schema JSON for tool:", tool?.id, e);
      return { properties: {}, required: [] };
    }
  }

  return { properties: {}, required: [] };
}

function renderGatewayToolsForTesting(tools) {
  const toolsDiv = safeGetElement("gateway-bulk-test-tools");
  if (!toolsDiv) return;

  if (!Array.isArray(tools) || tools.length === 0) {
    toolsDiv.innerHTML = `<div class="text-sm text-gray-600 dark:text-white">
      No enabled tools found for this gateway.
    </div>`;
    return;
  }

  const html = tools.map((tool) => {
    const { properties, required } = normalizeInputSchema(tool);

    const fields = Object.keys(properties).map((key) => {
      const p = properties[key] || {};
      const type = p.type || "string";
      const desc = p.description || "";
      const req = required.includes(key);

      // JSON textarea for object/array
      if (type === "object" || type === "array") {
        return `
          <div class="col-span-2">
            <label class="block text-sm font-medium text-gray-700 dark:text-white">
              ${escapeHtml(key)}${req ? ' <span class="text-red-500">*</span>' : ""}
            </label>
            <textarea
              class="mt-1 block w-full rounded-md border border-gray-300 dark:border-gray-400 shadow-sm focus:figma-blue-border focus:ring-indigo-500 bg-white dark:bg-white text-gray-900 dark:text-gray-900 font-mono text-xs p-2"
              rows="4"
              placeholder="${type === "object" ? "{ } (JSON)" : "[ ] (JSON)"}"
              data-tool-param="1"
              data-tool-id="${escapeHtml(tool.id)}"
              data-key="${escapeHtml(key)}"
              data-type="${escapeHtml(type)}"
            ></textarea>
            ${desc ? `<p class="mt-1 text-sm text-gray-500">${escapeHtml(desc)}</p>` : ""}
          </div>
        `;
      }

      // boolean select
      if (type === "boolean") {
        return `
          <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-white">
              ${escapeHtml(key)}${req ? ' <span class="text-red-500">*</span>' : ""}
            </label>
            <select
              class="mt-1 selectfield border border-gray-300 dark:border-gray-400 shadow-sm focus:figma-blue-border focus:ring-indigo-500 bg-white dark:bg-white text-gray-900 dark:text-gray-900"
              data-tool-param="1"
              data-tool-id="${escapeHtml(tool.id)}"
              data-key="${escapeHtml(key)}"
              data-type="boolean"
            >
              <option value="">None</option>
              <option value="true">true</option>
              <option value="false">false</option>
            </select>
            ${desc ? `<p class="mt-1 text-sm text-gray-500">${escapeHtml(desc)}</p>` : ""}
          </div>
        `;
      }

      // default input
      const inputType = (type === "number" || type === "integer") ? "number" : "text";
      return `
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-white">
            ${escapeHtml(key)}${req ? ' <span class="text-red-500">*</span>' : ""}
          </label>
          <input
            type="${inputType}"
            class="mt-1 block textfield rounded-md border border-gray-300 dark:border-gray-400 shadow-sm focus:figma-blue-border focus:ring-indigo-500 bg-white dark:bg-white placeholder-gray-400 dark:placeholder-gray-500 text-gray-900 dark:text-gray-900"
            placeholder="${escapeHtml(desc || "")}"
            data-tool-param="1"
            data-tool-id="${escapeHtml(tool.id)}"
            data-key="${escapeHtml(key)}"
            data-type="${escapeHtml(type)}"
          />
          ${desc ? `<p class="mt-1 text-sm text-gray-500">${escapeHtml(desc)}</p>` : ""}
        </div>
      `;
    }).join("");

    // IMPORTANT: remove "content" class (it hides due to your toggle CSS)
    return `
      <div class="bg-white shadow rounded-lg p-4 dark:bg-gray-800">
        <div class="flex items-start justify-between gap-3">
          <div class="min-w-0">
            <div class="flex items-center gap-2">
              <input
                type="checkbox"
                class="form-checkbox h-5 w-5 figma-blue-txt dark:bg-gray-800 dark:border-gray-600"
                data-tool-select="1"
                value="${escapeHtml(tool.id)}"
              />
              <div class="text-gray-800 dark:text-gray-100 font-bold truncate">
                ${escapeHtml(tool.name || "Unnamed tool")}
              </div>
            </div>
            ${tool.description ? `<div class="mt-1 text-sm text-gray-600 dark:text-white">
              ${escapeHtml(tool.description)}
            </div>` : ""}
            <div class="mt-1 text-xs text-gray-500 dark:text-white font-mono">${escapeHtml(tool.id)}</div>
          </div>

          <button
            type="button"
            class="px-3 py-1 border border-blue-600 rounded bg-white text-gray-700 hover:bg-gray-200 dark:bg-gray-900 dark:text-gray-200 dark:hover:bg-gray-700"
            onclick="toggleToolParams('${escapeHtml(tool.id)}', this)"
          >
            Show Inputs
          </button>
        </div>

        <div id="tool-params-${escapeHtml(tool.id)}" class="mt-4 hidden">
          ${Object.keys(properties).length === 0
            ? `<div class="text-sm text-gray-600 dark:text-white">This tool has no input parameters.</div>`
            : `<div class="grid grid-cols-2 gap-6">${fields}</div>`
          }

          <div class="mt-4 flex gap-2">
            <button type="button"
              class="btn-primary text-white focus:outline-none px-3 py-1"
              onclick="runSingleToolFromModal('${escapeHtml(tool.id)}')">
              Run this tool
            </button>

            <button type="button"
              class="px-3 py-1 border border-blue-600 rounded bg-white text-gray-700 hover:bg-gray-200 dark:bg-gray-900 dark:text-gray-200 dark:hover:bg-gray-700"
              onclick="clearToolInputs('${escapeHtml(tool.id)}')">
              Clear inputs
            </button>
          </div>

          <div id="tool-result-${escapeHtml(tool.id)}" class="mt-4 hidden"></div>
        </div>
      </div>
    `;
  }).join("");

  toolsDiv.innerHTML = html;
}


/* Toggle inputs panel */
function toggleToolParams(toolId, btnEl) {
  const panel = safeGetElement(`tool-params-${toolId}`);
  if (!panel) return;

  const willShow = panel.classList.contains("hidden");
  panel.classList.toggle("hidden", !willShow);

  if (btnEl) btnEl.textContent = willShow ? "Hide Inputs" : "Show Inputs";
}

/* ---------- Collect params from the rendered inputs ---------- */
function collectParamsForTool(toolId) {
  const inputs = document.querySelectorAll(
    `#gateway-bulk-test-modal [data-tool-param="1"][data-tool-id="${CSS.escape(toolId)}"]`
  );

  const params = {};
  for (const el of inputs) {
    const key = el.getAttribute("data-key");
    const type = el.getAttribute("data-type") || "string";
    const raw = (el.value ?? "").trim();

    if (!key) continue;
    if (raw === "") continue;

    if (type === "boolean") {
      if (raw === "true") params[key] = true;
      else if (raw === "false") params[key] = false;
      continue;
    }

    if (type === "number" || type === "integer") {
      const num = Number(raw);
      if (!Number.isFinite(num)) throw new Error(`Invalid number for ${key}`);
      params[key] = num;
      continue;
    }

    if (type === "object" || type === "array") {
      try {
        params[key] = JSON.parse(raw);
      } catch {
        throw new Error(`Invalid JSON for "${key}"`);
      }
      continue;
    }

    params[key] = raw;
  }

  return params;
}

/* ---------- Bulk test runner ---------- */
async function runBulkTests(mode) {
  const loading = safeGetElement("gateway-bulk-test-loading");
  const errorDiv = safeGetElement("gateway-bulk-test-error");
  const resultsDiv = safeGetElement("gateway-bulk-test-results");
  const resultsList = safeGetElement("gateway-bulk-test-results-list");

  try {
    if (errorDiv) {
      errorDiv.classList.add("hidden");
      errorDiv.innerHTML = "";
    }
    if (loading) loading.classList.remove("hidden");

    let toolIds = [];
    if (mode === "all") {
      const all = gatewayBulkTestInspectCache?.tools || [];
      toolIds = all.map((t) => t.id);
    } else {
      const checked = document.querySelectorAll(`#gateway-bulk-test-modal [data-tool-select="1"]:checked`);
      toolIds = Array.from(checked).map((c) => c.value);
    }

    if (!toolIds.length) throw new Error("No tools selected");

    const tests = toolIds.map((toolId) => ({
      tool_id: toolId,
      params: collectParamsForTool(toolId),
    }));

    const url = `${window.ROOT_PATH}/gateway-testing/gateways/${gatewayBulkTestGatewayId}/tools/bulk-test`;

    const response = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ tests }),
    });

    if (!response.ok) {
      const txt = await response.text();
      throw new Error(`Bulk test failed (${response.status}): ${txt}`);
    }

    const data = await response.json();
    const results = Array.isArray(data.results) ? data.results : [];

    // global results
    if (resultsDiv) resultsDiv.classList.remove("hidden");
    if (resultsList) resultsList.innerHTML = results.map((r) => renderBulkResultCard(r, false)).join("");

    // per-tool results + auto open
    for (const r of results) {
      const perTool = safeGetElement(`tool-result-${r.tool_id}`);
      if (perTool) {
        perTool.classList.remove("hidden");
        perTool.innerHTML = renderBulkResultCard(r, true);
      }
      const paramsPanel = safeGetElement(`tool-params-${r.tool_id}`);
      if (paramsPanel) paramsPanel.classList.remove("hidden");
    }
  } catch (error) {
    console.error("Bulk tool test error:", error);
    if (errorDiv) {
      errorDiv.classList.remove("hidden");
      errorDiv.innerHTML = `
        <div class="rounded-md border border-red-200 bg-red-50 text-red-800 p-3 text-sm dark:border-red-800 dark:bg-red-900/20 dark:text-red-200">
          ❌ ${escapeHtml(error.message || String(error))}
        </div>
      `;
    }
  } finally {
    if (loading) loading.classList.add("hidden");
  }
}

/* Single tool helper */
async function runSingleToolFromModal(toolId) {
  await runBulkTestsForToolIds([toolId]);
}

async function runBulkTestsForToolIds(toolIds) {
  const loading = safeGetElement("gateway-bulk-test-loading");
  const errorDiv = safeGetElement("gateway-bulk-test-error");

  try {
    if (errorDiv) {
      errorDiv.classList.add("hidden");
      errorDiv.innerHTML = "";
    }
    if (loading) loading.classList.remove("hidden");

    const tests = toolIds.map((id) => ({
      tool_id: id,
      params: collectParamsForTool(id),
    }));

    const url = `${window.ROOT_PATH}/gateway-testing/gateways/${gatewayBulkTestGatewayId}/tools/bulk-test`;
    const response = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ tests }),
    });

    if (!response.ok) {
      const txt = await response.text();
      throw new Error(`Bulk test failed (${response.status}): ${txt}`);
    }

    const data = await response.json();
    const results = Array.isArray(data.results) ? data.results : [];
    for (const r of results) {
      const perTool = safeGetElement(`tool-result-${r.tool_id}`);
      if (perTool) {
        perTool.classList.remove("hidden");
        perTool.innerHTML = renderBulkResultCard(r, true);
      }
      const paramsPanel = safeGetElement(`tool-params-${r.tool_id}`);
      if (paramsPanel) paramsPanel.classList.remove("hidden");
    }
  } catch (error) {
    console.error("Single tool test error:", error);
    if (errorDiv) {
      errorDiv.classList.remove("hidden");
      errorDiv.innerHTML = `
        <div class="rounded-md border border-red-200 bg-red-50 text-red-800 p-3 text-sm dark:border-red-800 dark:bg-red-900/20 dark:text-red-200">
          ❌ ${escapeHtml(error.message || String(error))}
        </div>
      `;
    }
  } finally {
    if (loading) loading.classList.add("hidden");
  }
}

/* Clear tool inputs */
function clearToolInputs(toolId) {
  const inputs = document.querySelectorAll(
    `#gateway-bulk-test-modal [data-tool-param="1"][data-tool-id="${CSS.escape(toolId)}"]`
  );
  for (const el of inputs) el.value = "";

  const r = safeGetElement(`tool-result-${toolId}`);
  if (r) {
    r.classList.add("hidden");
    r.innerHTML = "";
  }
}

/* ---------- Pretty JSON block (same vibe as gateway test response) ---------- */
function renderPrettyJsonBox(title, obj, domId) {
  const raw = JSON.stringify(obj ?? null, null, 2);

  return `
    <div class="mt-2 bg-gray-100 p-2 rounded overflow-auto text-sm text-gray-800 max-h-64 dark:bg-gray-900 dark:text-white border border-gray-200 dark:border-gray-700">
      <div class="flex items-center justify-between mb-2">
        <div class="text-sm font-medium text-gray-700 dark:text-white">${escapeHtml(title)}</div>
        <button
          type="button"
          class="px-3 py-1 border border-blue-600 rounded bg-white text-gray-700 hover:bg-gray-200 dark:bg-gray-800 dark:text-gray-200 dark:hover:bg-gray-700"
          onclick="copyJsonById('${domId}')"
        >
          Copy
        </button>
      </div>
      <pre id="${domId}" class="whitespace-pre-wrap font-mono text-xs text-gray-900 dark:text-white">${escapeHtml(raw)}</pre>
    </div>
  `;
}

async function copyJsonById(domId) {
  const el = document.getElementById(domId);
  if (!el) return;
  const text = el.textContent || "";
  await copyTextToClipboard(text);
}

/* ---------- Result card (styled like admin UI) ---------- */
function renderBulkResultCard(r, compact = false) {
  const success = !!r.success;
  const icon = success ? "✅" : "❌";

  const statusBadge = success
    ? `<span class="text-sm font-medium text-green-600">Success</span>`
    : `<span class="text-sm font-medium text-red-600">Failed</span>`;

  const err = r.error
    ? `<div class="mt-3 rounded-md border border-red-200 bg-red-50 text-red-800 p-3 text-sm dark:border-red-800 dark:bg-red-900/20 dark:text-red-200">
         ❌ ${escapeHtml(r.error)}
       </div>`
    : "";

  const rpcId = `rpc-${escapeHtml(r.tool_id || "tool")}-${Math.random().toString(16).slice(2)}`;
  const resId = `res-${escapeHtml(r.tool_id || "tool")}-${Math.random().toString(16).slice(2)}`;

  return `
    <div class="bg-white shadow rounded-lg p-4 dark:bg-gray-800">
      <div class="flex items-start justify-between gap-3">
        <div class="min-w-0">
          <div class="font-bold text-gray-800 dark:text-gray-100 truncate">
            ${icon} ${escapeHtml(r.tool_name || r.tool_id || "Tool")}
          </div>
          ${compact ? "" : `<div class="mt-1 text-xs text-gray-500 dark:text-white font-mono">${escapeHtml(r.tool_id || "")}</div>`}
        </div>
        ${statusBadge}
      </div>

      ${err}

      <details class="mt-4" ${compact ? "" : "open"}>
        <summary class="cursor-pointer text-sm font-medium text-gray-700 dark:text-white">
          RPC Envelope
        </summary>
        ${renderPrettyJsonBox("RPC", r.rpc ?? {}, rpcId)}
      </details>

      <details class="mt-4" ${compact ? "" : "open"}>
        <summary class="cursor-pointer text-sm font-medium text-gray-700 dark:text-white">
          Result
        </summary>
        ${renderPrettyJsonBox("Result", r.result ?? null, resId)}
      </details>
    </div>
  `;
}

/* ---------- Close + cleanup ---------- */
function handleGatewayBulkTestClose() {
  try {
    const toolsDiv = safeGetElement("gateway-bulk-test-tools");
    const resultsDiv = safeGetElement("gateway-bulk-test-results");
    const resultsList = safeGetElement("gateway-bulk-test-results-list");
    const errorDiv = safeGetElement("gateway-bulk-test-error");
    const summaryDiv = safeGetElement("gateway-bulk-test-summary");

    if (toolsDiv) toolsDiv.innerHTML = "";
    if (resultsList) resultsList.innerHTML = "";
    if (resultsDiv) resultsDiv.classList.add("hidden");
    if (errorDiv) {
      errorDiv.classList.add("hidden");
      errorDiv.innerHTML = "";
    }
    if (summaryDiv) summaryDiv.classList.add("hidden");

    gatewayBulkTestGatewayId = null;
    gatewayBulkTestInspectCache = null;

    closeModal("gateway-bulk-test-modal");
  } catch (error) {
    console.error("Error closing bulk test modal:", error);
  }
}

function cleanupGatewayBulkTestModal() {
  try {
    const reloadBtn = safeGetElement("gateway-bulk-test-reload");
    const runSelectedBtn = safeGetElement("gateway-bulk-test-run-selected");
    const runAllBtn = safeGetElement("gateway-bulk-test-run-all");
    const closeBtn = safeGetElement("gateway-bulk-test-close");

    if (reloadBtn && gatewayBulkTestReloadHandler) {
      reloadBtn.removeEventListener("click", gatewayBulkTestReloadHandler);
      gatewayBulkTestReloadHandler = null;
    }
    if (runSelectedBtn && gatewayBulkTestRunSelectedHandler) {
      runSelectedBtn.removeEventListener("click", gatewayBulkTestRunSelectedHandler);
      gatewayBulkTestRunSelectedHandler = null;
    }
    if (runAllBtn && gatewayBulkTestRunAllHandler) {
      runAllBtn.removeEventListener("click", gatewayBulkTestRunAllHandler);
      gatewayBulkTestRunAllHandler = null;
    }
    if (closeBtn && gatewayBulkTestCloseHandler) {
      closeBtn.removeEventListener("click", gatewayBulkTestCloseHandler);
      gatewayBulkTestCloseHandler = null;
    }

    console.log("✓ Cleaned up gateway bulk test modal listeners");
  } catch (error) {
    console.error("Error cleaning up bulk test modal:", error);
  }
}

/* Expose to window for inline onclick usage */
window.openGatewayToolTesting = openGatewayToolTesting;
window.toggleToolParams = toggleToolParams;
window.runSingleToolFromModal = runSingleToolFromModal;
window.clearToolInputs = clearToolInputs;
window.copyJsonById = copyJsonById;

// ===================================================================
// ENHANCED TOOL VIEWING with Secure Display
// ===================================================================

/**
 * SECURE: View Tool function with safe display
 */
async function viewTool(toolId) {
  try {
    console.log(`Fetching tool details for ID: ${toolId}`);

    const response = await fetchWithTimeout(
      `${window.ROOT_PATH}/tools/${toolId}`,
    );

    // ✅ Use your standard backend message parser (like servers/gateways)
    const { data: tool, message } = await readBackendMessage(response);

    if (!response.ok) {
      // ✅ Prefer backend message (RBAC, not found, validation errors, etc.)
      throw new Error(message || `Failed to load tool (HTTP ${response.status})`);
    }

    // Build auth HTML safely with new styling
    let authHTML = "";
    if (tool.auth?.username && tool.auth?.password) {
      authHTML = `
        <span class="font-medium text-gray-700 dark:text-gray-300">Authentication Type:</span>
        <div class="mt-1 text-sm">
          <div class="text-gray-600 dark:text-gray-400">Basic Authentication</div>
          <div class="mt-1">Username: <span class="auth-username font-medium"></span></div>
          <div>Password: <span class="font-medium">********</span></div>
        </div>
      `;
    } else if (tool.auth?.token) {
      authHTML = `
        <span class="font-medium text-gray-700 dark:text-gray-300">Authentication Type:</span>
        <div class="mt-1 text-sm">
          <div class="text-gray-600 dark:text-gray-400">Bearer Token</div>
          <div class="mt-1">Token: <span class="font-medium">********</span></div>
        </div>
      `;
    } else if (tool.auth?.authHeaderKey && tool.auth?.authHeaderValue) {
      authHTML = `
        <span class="font-medium text-gray-700 dark:text-gray-300">Authentication Type:</span>
        <div class="mt-1 text-sm">
          <div class="text-gray-600 dark:text-gray-400">Custom Headers</div>
          <div class="mt-1">Header: <span class="auth-header-key font-medium"></span></div>
          <div>Value: <span class="font-medium">********</span></div>
        </div>
      `;
    } else {
      authHTML = `
        <span class="font-medium text-gray-700 dark:text-gray-300">Authentication Type:</span>
        <div class="mt-1 text-sm">None</div>
      `;
    }

    // Create annotation badges safely - NO ESCAPING since we're using textContent
    const renderAnnotations = (annotations) => {
      if (!annotations || Object.keys(annotations).length === 0) {
        return '<p><strong>Annotations:</strong> <span class="text-gray-600 dark:text-gray-300">None</span></p>';
      }

      const badges = [];

      if (annotations.title) {
        badges.push(
          '<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 mr-1 mb-1 annotation-title"></span>',
        );
      }

      if (annotations.readOnlyHint === true) {
        badges.push(
          '<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 mr-1 mb-1">📖 Read-Only</span>',
        );
      }
      if (annotations.destructiveHint === true) {
        badges.push(
          '<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800 mr-1 mb-1">⚠️ Destructive</span>',
        );
      }
      if (annotations.idempotentHint === true) {
        badges.push(
          '<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800 mr-1 mb-1">🔄 Idempotent</span>',
        );
      }
      if (annotations.openWorldHint === true) {
        badges.push(
          '<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800 mr-1 mb-1">🌐 External Access</span>',
        );
      }

      Object.keys(annotations).forEach((key) => {
        if (!["title", "readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"].includes(key)) {
          const value = annotations[key];
          badges.push(
            `<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600 dark:text-gray-200 mr-1 mb-1 custom-annotation" data-key="${key}" data-value="${value}"></span>`,
          );
        }
      });

      return `
        <div>
          <strong>Annotations:</strong>
          <div class="mt-1 flex flex-wrap">
            ${badges.join("")}
          </div>
        </div>
      `;
    };

    const toolDetailsDiv = safeGetElement("tool-details");
    if (toolDetailsDiv) {
      const safeHTML = `
        <div class="bg-transparent dark:bg-transparent dark:text-gray-300">
          <div class="grid grid-cols-2 gap-6 mb-6">
            <div class="space-y-3">
              <div>
                <span class="font-medium text-gray-700 dark:text-gray-300">Display Name:</span>
                <div class="mt-1 tool-display-name font-medium"></div>
              </div>
              <div>
                <span class="font-medium text-gray-700 dark:text-gray-300">Technical Name:</span>
                <div class="mt-1 tool-name text-sm"></div>
              </div>
              <div>
                <span class="font-medium text-gray-700 dark:text-gray-300">URL:</span>
                <div class="mt-1 tool-url text-sm"></div>
              </div>
              <div>
                <span class="font-medium text-gray-700 dark:text-gray-300">Type:</span>
                <div class="mt-1 tool-type text-sm"></div>
              </div>
            </div>

            <div class="space-y-3">
              <div>
                <span class="font-medium text-gray-700 dark:text-gray-300">Description:</span>
                <div class="mt-1 tool-description text-sm"></div>
              </div>
              <div>
                <span class="font-medium text-gray-700 dark:text-gray-300">Tags:</span>
                <div class="mt-1 tool-tags text-sm"></div>
              </div>
              <div>
                <span class="font-medium text-gray-700 dark:text-gray-300">Request Type:</span>
                <div class="mt-1 tool-request-type text-sm"></div>
              </div>
              <div class="auth-info">
                ${authHTML}
              </div>
            </div>
          </div>

          <div class="mb-6">
            ${renderAnnotations(tool.annotations)}
          </div>

          <div class="space-y-4">
            <div>
              <strong class="text-gray-700 dark:text-gray-300">Headers:</strong>
              <pre class="mt-1 bg-gray-100 p-3 rounded text-xs dark:bg-gray-800 dark:text-gray-200 tool-headers overflow-x-auto"></pre>
            </div>
            <div>
              <strong class="text-gray-700 dark:text-gray-300">Input Schema:</strong>
              <pre class="mt-1 bg-gray-100 p-3 rounded text-xs dark:bg-gray-800 dark:text-gray-200 tool-schema overflow-x-auto"></pre>
            </div>
          </div>

          <div class="mt-6 pt-4 border-t border-gray-200 dark:border-gray-600">
            <strong class="text-gray-700 dark:text-gray-300">Metrics:</strong>
            <div class="grid grid-cols-2 gap-4 mt-3 text-sm">
              <div class="space-y-2">
                <div class="flex justify-between">
                  <span class="text-gray-600 dark:text-gray-400">Total Executions:</span>
                  <span class="metric-total font-medium"></span>
                </div>
                <div class="flex justify-between">
                  <span class="text-gray-600 dark:text-gray-400">Successful Executions:</span>
                  <span class="metric-success font-medium text-green-600"></span>
                </div>
                <div class="flex justify-between">
                  <span class="text-gray-600 dark:text-gray-400">Failed Executions:</span>
                  <span class="metric-failed font-medium text-red-600"></span>
                </div>
                <div class="flex justify-between">
                  <span class="text-gray-600 dark:text-gray-400">Failure Rate:</span>
                  <span class="metric-failure-rate font-medium"></span>
                </div>
              </div>
              <div class="space-y-2">
                <div class="flex justify-between">
                  <span class="text-gray-600 dark:text-gray-400">Min Response Time:</span>
                  <span class="metric-min-time font-medium"></span>
                </div>
                <div class="flex justify-between">
                  <span class="text-gray-600 dark:text-gray-400">Max Response Time:</span>
                  <span class="metric-max-time font-medium"></span>
                </div>
                <div class="flex justify-between">
                  <span class="text-gray-600 dark:text-gray-400">Average Response Time:</span>
                  <span class="metric-avg-time font-medium"></span>
                </div>
                <div class="flex justify-between">
                  <span class="text-gray-600 dark:text-gray-400">Last Execution Time:</span>
                  <span class="metric-last-time font-medium"></span>
                </div>
              </div>
            </div>
          </div>

          <div class="mt-6 border-t pt-4">
            <strong>Metadata:</strong>
            <div class="grid grid-cols-2 gap-4 mt-2 text-sm">
              <div>
                <span class="font-medium text-gray-600 dark:text-gray-400">Created By:</span>
                <span class="ml-2 metadata-created-by"></span>
              </div>
              <div>
                <span class="font-medium text-gray-600 dark:text-gray-400">Created At:</span>
                <span class="ml-2 metadata-created-at"></span>
              </div>
              <div>
                <span class="font-medium text-gray-600 dark:text-gray-400">Created From:</span>
                <span class="ml-2 metadata-created-from"></span>
              </div>
              <div>
                <span class="font-medium text-gray-600 dark:text-gray-400">Created Via:</span>
                <span class="ml-2 metadata-created-via"></span>
              </div>
              <div>
                <span class="font-medium text-gray-600 dark:text-gray-400">Last Modified By:</span>
                <span class="ml-2 metadata-modified-by"></span>
              </div>
              <div>
                <span class="font-medium text-gray-600 dark:text-gray-400">Last Modified At:</span>
                <span class="ml-2 metadata-modified-at"></span>
              </div>
              <div>
                <span class="font-medium text-gray-600 dark:text-gray-400">Version:</span>
                <span class="ml-2 metadata-version"></span>
              </div>
              <div>
                <span class="font-medium text-gray-600 dark:text-gray-400">Import Batch:</span>
                <span class="ml-2 metadata-import-batch"></span>
              </div>
            </div>
          </div>
        </div>
      `;

      safeSetInnerHTML(toolDetailsDiv, safeHTML, true);

      const setTextSafely = (selector, value) => {
        const element = toolDetailsDiv.querySelector(selector);
        if (element) element.textContent = value || "N/A";
      };

      setTextSafely(".tool-display-name", tool.displayName || tool.customName || tool.name);
      setTextSafely(".tool-name", tool.name);
      setTextSafely(".tool-url", tool.url);
      setTextSafely(".tool-type", tool.integrationType);
      setTextSafely(".tool-description", tool.description);

      const tagsElement = toolDetailsDiv.querySelector(".tool-tags");
      if (tagsElement) {
        if (tool.tags && tool.tags.length > 0) {
          tagsElement.innerHTML = tool.tags
            .map((tag) => `<span class="inline-block bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full mr-1 mb-1 dark:bg-blue-900 dark:text-blue-200">${escapeHtml(tag)}</span>`)
            .join("");
        } else {
          tagsElement.textContent = "None";
        }
      }

      setTextSafely(".tool-request-type", tool.requestType);
      setTextSafely(".tool-headers", JSON.stringify(tool.headers || {}, null, 2));
      setTextSafely(".tool-schema", JSON.stringify(tool.inputSchema || {}, null, 2));

      if (tool.auth?.username) setTextSafely(".auth-username", tool.auth.username);
      if (tool.auth?.authHeaderKey) setTextSafely(".auth-header-key", tool.auth.authHeaderKey);
      if (tool.annotations?.title) setTextSafely(".annotation-title", tool.annotations.title);

      const customAnnotations = toolDetailsDiv.querySelectorAll(".custom-annotation");
      customAnnotations.forEach((element) => {
        const key = element.dataset.key;
        const value = element.dataset.value;
        element.textContent = `${key}: ${value}`;
      });

      setTextSafely(".metric-total", tool.metrics?.totalExecutions ?? 0);
      setTextSafely(".metric-success", tool.metrics?.successfulExecutions ?? 0);
      setTextSafely(".metric-failed", tool.metrics?.failedExecutions ?? 0);
      setTextSafely(".metric-failure-rate", tool.metrics?.failureRate ?? 0);
      setTextSafely(".metric-min-time", tool.metrics?.minResponseTime ?? "N/A");
      setTextSafely(".metric-max-time", tool.metrics?.maxResponseTime ?? "N/A");
      setTextSafely(".metric-avg-time", tool.metrics?.avgResponseTime ?? "N/A");
      setTextSafely(".metric-last-time", tool.metrics?.lastExecutionTime ?? "N/A");

      setTextSafely(".metadata-created-by", tool.created_by || tool.createdBy || "Legacy Entity");
      setTextSafely(
        ".metadata-created-at",
        tool.created_at ? new Date(tool.created_at).toLocaleString()
          : tool.createdAt ? new Date(tool.createdAt).toLocaleString()
          : "Pre-metadata",
      );
      setTextSafely(".metadata-created-from", tool.created_from_ip || tool.createdFromIp || "Unknown");
      setTextSafely(".metadata-created-via", tool.created_via || tool.createdVia || "Unknown");
      setTextSafely(".metadata-modified-by", tool.modified_by || tool.modifiedBy || "N/A");
      setTextSafely(
        ".metadata-modified-at",
        tool.updated_at ? new Date(tool.updated_at).toLocaleString()
          : tool.updatedAt ? new Date(tool.updatedAt).toLocaleString()
          : "N/A",
      );
      setTextSafely(".metadata-modified-from", tool.modified_from_ip || tool.modifiedFromIp || "N/A");
      setTextSafely(".metadata-modified-via", tool.modified_via || tool.modifiedVia || "N/A");
      setTextSafely(".metadata-version", tool.version || "1");
      setTextSafely(".metadata-import-batch", tool.import_batch_id || tool.importBatchId || "N/A");
    }

    openModal("tool-modal");
    console.log("✓ Tool details loaded successfully");
  } catch (error) {
    console.error("Error fetching tool details:", error);

    // ✅ Prefer backend/validation-friendly message everywhere
    const msg = error?.message || "Failed to load tool details";
    showErrorMessage(msg);
  }
}

// ===================================================================
// MISC UTILITY FUNCTIONS
// ===================================================================

function copyJsonToClipboard(sourceId) {
    const el = safeGetElement(sourceId);
    if (!el) {
        console.warn(
            `[copyJsonToClipboard] Source element "${sourceId}" not found.`,
        );
        return;
    }

    const text = "value" in el ? el.value : el.textContent;

    navigator.clipboard.writeText(text).then(
        () => {
            console.info("JSON copied to clipboard ✔️");
            if (el.dataset.toast !== "off") {
                showSuccessMessage("Copied!");
            }
        },
        (err) => {
            console.error("Clipboard write failed:", err);
            showErrorMessage("Unable to copy to clipboard");
        },
    );
}

// Make it available to inline onclick handlers
window.copyJsonToClipboard = copyJsonToClipboard;

// ===================================================================
// ENHANCED FORM HANDLERS with Input Validation
// ===================================================================
async function handleGatewayFormSubmit(e) {
  e.preventDefault();

  const form = e.target;
  const formData = new FormData(form);
  const status = safeGetElement("status-gateways");
  const loading = safeGetElement("add-gateway-loading");

  try {
    const name = formData.get("name");
    const url = formData.get("url");

    const nameValidation = validateInputName(name, "gateway");
    const urlValidation = validateUrl(url);

    if (!nameValidation.valid) throw new Error(nameValidation.error);
    if (!urlValidation.valid) throw new Error(urlValidation.error);

    if (loading) loading.style.display = "block";
    if (status) {
      status.textContent = "";
      status.classList.remove("error-status");
    }

    const isInactiveCheckedBool = isInactiveChecked("gateways");

    // ---- Build JSON payload (instead of FormData) ----
    const payload = {
      name: nameValidation.value,
      url: urlValidation.value,
      description: (formData.get("description") || "").trim() || null,
      transport: formData.get("transport") || "SSE",
      auth_type: formData.get("auth_type") || "",
      visibility: formData.get("visibility") || "public",
      is_inactive_checked: !!isInactiveCheckedBool,
    };

    // tags: "a,b,c" -> ["a","b","c"]
    const tagsRaw = (formData.get("tags") || "").trim();
    if (tagsRaw) {
      payload.tags = tagsRaw.split(",").map(t => t.trim()).filter(Boolean);
    } else {
      payload.tags = [];
    }

    // passthrough_headers: "A,B" -> ["A","B"]
    const phRaw = (formData.get("passthrough_headers") || "").trim();
    if (phRaw) {
      const ph = phRaw.split(",").map(h => h.trim()).filter(Boolean);
      for (const headerName of ph) {
        if (!HEADER_NAME_REGEX.test(headerName)) {
          throw new Error(
            `Invalid passthrough header name: "${headerName}". Only letters, numbers, and hyphens are allowed.`
          );
        }
      }
      payload.passthrough_headers = ph;
    } else {
      payload.passthrough_headers = [];
    }

    // Auth details (same inputs, just mapped into JSON)
    if (payload.auth_type === "basic") {
      payload.auth_username = (formData.get("auth_username") || "").trim() || null;
      payload.auth_password = (formData.get("auth_password") || "").trim() || null;
    } else if (payload.auth_type === "bearer") {
      payload.auth_token = (formData.get("auth_token") || "").trim() || null;
    } else if (payload.auth_type === "authheaders") {
      const authHeadersJson = (formData.get("auth_headers") || "").trim();
      // keep your existing dynamic header builder behavior
      if (authHeadersJson) {
        try {
          const parsed = JSON.parse(authHeadersJson);
          payload.auth_headers = Array.isArray(parsed) ? parsed : [];
        } catch {
          payload.auth_headers = [];
        }
      } else {
        payload.auth_headers = [];
      }
    } else if (payload.auth_type === "oauth") {
      const oauthConfig = {
        grant_type: formData.get("oauth_grant_type") || "client_credentials",
        client_id: (formData.get("oauth_client_id") || "").trim() || null,
        client_secret: (formData.get("oauth_client_secret") || "").trim() || null,
        token_url: (formData.get("oauth_token_url") || "").trim() || null,
        scopes: (formData.get("oauth_scopes") || "")
          .split(" ")
          .map(s => s.trim())
          .filter(Boolean),
      };

      if (oauthConfig.grant_type === "authorization_code") {
        oauthConfig.authorization_url = (formData.get("oauth_authorization_url") || "").trim() || null;
        oauthConfig.redirect_uri = (formData.get("oauth_redirect_uri") || "").trim() || null;
        oauthConfig.token_management = {
          store_tokens: formData.get("oauth_store_tokens") === "on",
          auto_refresh: formData.get("oauth_auto_refresh") === "on",
          refresh_threshold_seconds: 300,
        };
      }

      payload.oauth_config = oauthConfig;
    }

    const teamId = new URL(window.location.href).searchParams.get("team_id");
    if (teamId) payload.team_id = teamId;

    // ---- POST JSON (this fixes your 422) ----
    const headers = await rbacHeaders(); // includes Authorization + Content-Type
    const response = await fetchWithTimeout(`${window.ROOT_PATH}/gateways`, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    });

    // ✅ Robust parse (JSON / text) + robust message extraction
    let result = null;
    let backendMessage = "";

    try {
    const ct = (response.headers.get("content-type") || "").toLowerCase();
    if (ct.includes("application/json")) {
        result = await response.json();
    } else {
        result = await response.text();
    }
    } catch (parseErr) {
    // If response has no body or invalid JSON
    result = null;
    }

    // Extract a clean message for ANY payload shape
    if (typeof result === "string") {
    backendMessage = result.trim();
    } else if (result && typeof result === "object") {
    // FastAPI commonly uses: { detail: "..." } OR { detail: [ {msg:...}, ... ] }
    if (Array.isArray(result.detail)) {
        backendMessage = result.detail
        .map((d) => d?.msg || d?.message || JSON.stringify(d))
        .join(" | ");
    } else if (typeof result.detail === "string") {
        backendMessage = result.detail;
    } else if (typeof result.message === "string") {
        backendMessage = result.message;
    } else if (typeof result.error === "string") {
        backendMessage = result.error;
    } else {
        backendMessage = JSON.stringify(result);
    }
    } else {
    backendMessage = "";
    }

    // If HTTP failed, throw the backend message (permissions/422/etc.)
    if (!response.ok) {
    throw new Error(backendMessage || `Failed to add gateway (HTTP ${response.status})`);
    }

    // Accept both formats:
    // 1) { success: true, message: "..."} (old)
    // 2) Gateway object { id: "...", name: "...", url: "..."} (new)
    const ok =
    (result && result.success === true) ||
    (result && typeof result === "object" && !!result.id);

    if (!ok) {
    throw new Error(backendMessage || "Failed to add gateway");
    }

    // ✅ keep your redirect refresh exactly the same
    const searchParams = new URLSearchParams();
    if (isInactiveCheckedBool) searchParams.set("include_inactive", "true");
    if (teamId) searchParams.set("team_id", teamId);

    const queryString = searchParams.toString();
    const redirectUrl = `${window.ROOT_PATH}/admin${queryString ? `?${queryString}` : ""}#gateways`;
    window.location.href = redirectUrl;

  } catch (error) {
    console.error("Error:", error);
    if (status) {
      status.textContent = error.message || "An error occurred!";
      status.classList.add("error-status");
    }
    showErrorMessage(String(error?.message || error || "An error occurred!"));
  } finally {
    if (loading) loading.style.display = "none";
  }
}


async function handleResourceFormSubmit(e) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);
    const status = safeGetElement("status-resources");
    const loading = safeGetElement("add-resource-loading");
    try {
        // Validate inputs
        const name = formData.get("name");
        const uri = formData.get("uri");
        const nameValidation = validateInputName(name, "resource");
        const uriValidation = validateInputName(uri, "resource URI");

        if (!nameValidation.valid) {
            showErrorMessage(nameValidation.error);
            return;
        }

        if (!uriValidation.valid) {
            showErrorMessage(uriValidation.error);
            return;
        }

        if (loading) {
            loading.style.display = "block";
        }
        if (status) {
            status.textContent = "";
            status.classList.remove("error-status");
        }

        const isInactiveCheckedBool = isInactiveChecked("resources");
        formData.append("is_inactive_checked", isInactiveCheckedBool);

        const response = await fetch(`${window.ROOT_PATH}/admin/resources`, {
            method: "POST",
            body: formData,
        });
        const result = await response.json();
        if (!result || !result.success) {
            throw new Error(result?.message || "Failed to add Resource");
        } else {
            const teamId = new URL(window.location.href).searchParams.get(
                "team_id",
            );

            const searchParams = new URLSearchParams();
            if (isInactiveCheckedBool) {
                searchParams.set("include_inactive", "true");
            }
            if (teamId) {
                searchParams.set("team_id", teamId);
            }
            const queryString = searchParams.toString();
            const redirectUrl = `${window.ROOT_PATH}/admin${queryString ? `?${queryString}` : ""}#resources`;
            window.location.href = redirectUrl;
        }
    } catch (error) {
        console.error("Error:", error);
        if (status) {
            status.textContent = error.message || "An error occurred!";
            status.classList.add("error-status");
        }
        showErrorMessage(error.message);
    } finally {
        // location.reload();
        if (loading) {
            loading.style.display = "none";
        }
    }
}

async function handlePromptFormSubmit(e) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);
    const status = safeGetElement("status-prompts");
    const loading = safeGetElement("add-prompts-loading");
    try {
        // Validate inputs
        const name = formData.get("name");
        const nameValidation = validateInputName(name, "prompt");

        if (!nameValidation.valid) {
            showErrorMessage(nameValidation.error);
            return;
        }

        if (loading) {
            loading.style.display = "block";
        }
        if (status) {
            status.textContent = "";
            status.classList.remove("error-status");
        }

        const isInactiveCheckedBool = isInactiveChecked("prompts");
        formData.append("is_inactive_checked", isInactiveCheckedBool);

        const response = await fetch(`${window.ROOT_PATH}/admin/prompts`, {
            method: "POST",
            body: formData,
        });
        const result = await response.json();
        if (!result || !result.success) {
            throw new Error(result?.message || "Failed to add prompt");
        }
        // Only redirect on success
        const teamId = new URL(window.location.href).searchParams.get(
            "team_id",
        );

        const searchParams = new URLSearchParams();
        if (isInactiveCheckedBool) {
            searchParams.set("include_inactive", "true");
        }
        if (teamId) {
            searchParams.set("team_id", teamId);
        }
        const queryString = searchParams.toString();
        const redirectUrl = `${window.ROOT_PATH}/admin${queryString ? `?${queryString}` : ""}#prompts`;
        window.location.href = redirectUrl;
    } catch (error) {
        console.error("Error:", error);
        if (status) {
            status.textContent = error.message || "An error occurred!";
            status.classList.add("error-status");
        }
        showErrorMessage(error.message);
    } finally {
        // location.reload();
        if (loading) {
            loading.style.display = "none";
        }
    }
}

async function handleEditPromptFormSubmit(e) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);

    try {
        // Validate inputs
        const name = formData.get("name");
        const nameValidation = validateInputName(name, "prompt");
        if (!nameValidation.valid) {
            showErrorMessage(nameValidation.error);
            return;
        }

        // Save CodeMirror editors' contents if present
        if (window.promptToolHeadersEditor) {
            window.promptToolHeadersEditor.save();
        }
        if (window.promptToolSchemaEditor) {
            window.promptToolSchemaEditor.save();
        }

        const isInactiveCheckedBool = isInactiveChecked("prompts");
        formData.append("is_inactive_checked", isInactiveCheckedBool);

        // Submit via fetch
        const response = await fetch(form.action, {
            method: "POST",
            body: formData,
        });

        const result = await response.json();
        if (!result || !result.success) {
            throw new Error(result?.message || "Failed to edit Prompt");
        }
        // Only redirect on success
        const teamId = new URL(window.location.href).searchParams.get(
            "team_id",
        );

        const searchParams = new URLSearchParams();
        if (isInactiveCheckedBool) {
            searchParams.set("include_inactive", "true");
        }
        if (teamId) {
            searchParams.set("team_id", teamId);
        }
        const queryString = searchParams.toString();
        const redirectUrl = `${window.ROOT_PATH}/admin${queryString ? `?${queryString}` : ""}#prompts`;
        window.location.href = redirectUrl;
    } catch (error) {
        console.error("Error:", error);
        showErrorMessage(error.message);
    }
}

async function handleServerFormSubmit(e) {
  e.preventDefault();

  const form = e.target;
  const formData = new FormData(form);

  const status = safeGetElement("serverFormError");
  const loading = safeGetElement("add-server-loading");

  try {
    const name = (formData.get("name") || "").toString();

    // Basic validation
    const nameValidation = validateInputName(name, "server");
    if (!nameValidation.valid) throw new Error(nameValidation.error);

    if (loading) loading.style.display = "block";
    if (status) {
      status.textContent = "";
      status.classList.remove("error-status");
    }

    const isInactiveCheckedBool = isInactiveChecked("servers");

    // team_id from query param (same as before)
    const teamId = new URL(window.location.href).searchParams.get("team_id");

    // ---- Build "server" payload expected by POST /servers ----
    // Convert checked checkboxes -> "id1,id2" comma list (same as your network payload)
    const associatedTools = Array.from(form.querySelectorAll('input[name="associatedTools"]:checked'))
      .map((el) => el.value)
      .filter(Boolean)
      .join(",");

    const associatedResources = Array.from(form.querySelectorAll('input[name="associatedResources"]:checked'))
      .map((el) => el.value)
      .filter(Boolean)
      .join(",");

    const associatedPrompts = Array.from(form.querySelectorAll('input[name="associatedPrompts"]:checked'))
      .map((el) => el.value)
      .filter(Boolean)
      .join(",");

    // tags: allow either comma-separated string OR empty
    const rawTags = (formData.get("tags") || "").toString();
    const tags = rawTags
      ? rawTags.split(",").map((t) => t.trim()).filter(Boolean)
      : [];

    // visibility: keep your existing field
    const visibility = (formData.get("visibility") || "public").toString();

    // id: if blank, omit (backend will auto-generate)
    const idRaw = formData.get("id");
    const id = idRaw && String(idRaw).trim() ? String(idRaw).trim() : undefined;

    const serverPayload = {
      ...(id ? { id } : {}),
      name: nameValidation.value,
      description: (formData.get("description") || "").toString(),
      icon: (formData.get("icon") || "").toString(),
      visibility,
      tags,
      associated_tools: associatedTools,         // ✅ backend expects these names
      associated_resources: associatedResources, // ✅
      associated_prompts: associatedPrompts,     // ✅
      ...(teamId ? { team_id: teamId } : {}),
    };

    // Wrap as { server: {...} }  ✅ REQUIRED by your backend
    const body = JSON.stringify({
      server: serverPayload,
      // keep this outside or inside depending on backend; safest: send both
      is_inactive_checked: !!isInactiveCheckedBool,
    });

    const headers = await rbacHeaders();
    headers["Content-Type"] = "application/json";

    const response = await fetchWithTimeout(`${window.ROOT_PATH}/servers`, {
      method: "POST",
      headers,
      body,
    });

    const { message } = await readBackendMessage(response);

    if (!response.ok) {
      throw new Error(message || `Failed to add server (HTTP ${response.status})`);
    }

    // ✅ Success redirect (same UX as before)
    const searchParams = new URLSearchParams();
    if (isInactiveCheckedBool) searchParams.set("include_inactive", "true");
    if (teamId) searchParams.set("team_id", teamId);

    const queryString = searchParams.toString();
    showSuccessMessage("Server created successfully.");

    setTimeout(() => {
    const redirectUrl = `${window.ROOT_PATH}/admin${queryString ? `?${queryString}` : ""}#catalog`;
    window.location.href = redirectUrl;
    }, 350);


    } catch (error) {
    console.error("Add Server Error:", error);

    const msg = error?.message || "An error occurred.";

    // Inline error (form-level)
    if (status) {
        status.textContent = msg;
        status.classList.add("error-status");
    }

    // Global toast/snackbar
    showErrorMessage(msg);
    }finally {
    if (loading) loading.style.display = "none";
  }
}


async function handleToolFormSubmit(event) {
  event.preventDefault();

  try {
    const form = event.target;
    const formData = new FormData(form);

    // Validate form inputs
    const name = formData.get("name");
    const url = formData.get("url");

    const nameValidation = validateInputName(name, "tool");
    const urlValidation = validateUrl(url);

    if (!nameValidation.valid) {
      throw new Error(nameValidation.error);
    }

    if (!urlValidation.valid) {
      throw new Error(urlValidation.error);
    }

    // If in UI mode, update schemaEditor with generated schema
    const mode = document.querySelector('input[name="schema_input_mode"]:checked');
    if (mode && mode.value === "ui") {
      if (window.schemaEditor) {
        const generatedSchema = generateSchema();
        const schemaValidation = validateJson(generatedSchema, "Generated Schema");
        if (!schemaValidation.valid) {
          throw new Error(schemaValidation.error);
        }
        window.schemaEditor.setValue(generatedSchema);
      }
    }

    // Save CodeMirror editors' contents
    if (window.headersEditor) {
      window.headersEditor.save();
    }
    if (window.schemaEditor) {
      window.schemaEditor.save();
    }

    // Keep existing include_inactive logic for redirect building
    const isInactiveCheckedBool = isInactiveChecked("tools");

    // -----------------------------
    // ✅ NEW: build JSON payload for POST /tools
    // -----------------------------
    const teamId = new URL(window.location.href).searchParams.get("team_id") || null;

    const visibility = (formData.get("visibility") || "private").toString();

    const safeParseJson = (val, fallback) => {
      const s = (val ?? "").toString().trim();
      if (!s) return fallback;
      try {
        return JSON.parse(s);
      } catch {
        return fallback;
      }
    };

    const toolPayload = {
      name: (formData.get("name") || "").toString(),
      displayName: (formData.get("displayName") || "").toString() || null,
      url: (formData.get("url") || "").toString(),
      description: (formData.get("description") || "").toString() || null,

      // API schema uses snake_case
      integration_type: (formData.get("integrationType") || "REST").toString(),
      request_type: (formData.get("requestType") || "GET").toString(),

      headers: safeParseJson(formData.get("headers"), {}),
      input_schema: safeParseJson(formData.get("input_schema"), {}),
      annotations: safeParseJson(formData.get("annotations"), {}),

      jsonpath_filter: (formData.get("jsonpath_filter") || "").toString(),

      tags: ((formData.get("tags") || "").toString())
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
    };

    const response = await fetch(`${window.ROOT_PATH}/tools`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tool: toolPayload,
        team_id: teamId,
        visibility: visibility,
      }),
    });

    const result = await response.json();

    // normalize error message (FastAPI uses detail sometimes)
    if (!response.ok || !result) {
      const msg =
        result?.message ||
        result?.detail ||
        "Failed to add tool";
      throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
    }

    // If API returns ToolRead (not {success:true}), treat 2xx as success
    // If it returns {success:false}, treat as failure
    if (result && result.success === false) {
      throw new Error(result?.message || "Failed to add tool");
    }

    // Redirect back to admin tools tab (preserve your existing behavior)
    const searchParams = new URLSearchParams();
    if (isInactiveCheckedBool) {
      searchParams.set("include_inactive", "true");
    }
    if (teamId) {
      searchParams.set("team_id", teamId);
    }
    const queryString = searchParams.toString();
    const redirectUrl = `${window.ROOT_PATH}/admin${queryString ? `?${queryString}` : ""}#tools`;
    window.location.href = redirectUrl;

  } catch (error) {
    console.error("Fetch error:", error);
    showErrorMessage(error.message);
  }
}

async function handleEditToolFormSubmit(event) {
  event.preventDefault();

  const form = event.target;

  try {
    const formData = new FormData(form);

    // Basic validation
    const name = formData.get("name");
    const url = formData.get("url");

    const nameValidation = validateInputName(name, "tool");
    const urlValidation = validateUrl(url);

    if (!nameValidation.valid) throw new Error(nameValidation.error);
    if (!urlValidation.valid) throw new Error(urlValidation.error);

    // Save CodeMirror editors' contents if present
    if (window.editToolHeadersEditor) window.editToolHeadersEditor.save();
    if (window.editToolSchemaEditor) window.editToolSchemaEditor.save();

    const isInactiveCheckedBool = isInactiveChecked("tools");

    // ---- helpers (inline, minimal) ----
    const parseJsonField = (raw, label, fallback) => {
      const txt = (raw ?? "").toString().trim();
      if (!txt) return fallback;
      const v = validateJson(txt, label);
      if (!v.valid) throw new Error(v.error || `Invalid JSON for ${label}`);
      return v.value;
    };

    const normalizeTags = (raw) =>
      (raw || "")
        .toString()
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);

    const visibility =
      formData.get("visibility") ||
      (safeGetElement("edit-tool-visibility-public")?.checked
        ? "public"
        : safeGetElement("edit-tool-visibility-team")?.checked
          ? "team"
          : safeGetElement("edit-tool-visibility-private")?.checked
            ? "private"
            : undefined);

    const teamId =
      formData.get("team_id") ||
      new URL(window.location.href).searchParams.get("team_id") ||
      undefined;

    // ---- build JSON payload for router PUT /tools/{id} ----
    const payload = {
      // NOTE: backend typically treats tool.name as immutable, so we prefer custom_name
      // If your backend allows name update, you can add: name: nameValidation.value
      custom_name: (formData.get("custom_name") || formData.get("customName") || "").toString().trim() || undefined,

      displayName: (formData.get("displayName") || "").toString(),

      url: urlValidation.value,
      description: (formData.get("description") || "").toString(),

      integration_type: (formData.get("integration_Type") || formData.get("integration_type") || "").toString().trim() || undefined,

      // request_type only matters for REST; for MCP it may be disabled/blank
      request_type: (formData.get("request_Type") || formData.get("request_type") || "").toString().trim() || undefined,

      headers: parseJsonField(formData.get("headers"), "Headers", {}),
      input_schema: parseJsonField(formData.get("input_schema"), "Schema", {}),
      annotations: parseJsonField(formData.get("annotations"), "Annotations", {}),

      jsonpath_filter: (formData.get("jsonpath_filter") || "").toString(),
      tags: normalizeTags(formData.get("tags")),
      visibility: visibility || undefined,
      team_id: teamId,

      // keep your UI behavior
      is_inactive_checked: !!isInactiveCheckedBool,
    };

    // Submit via fetch (✅ PUT JSON + RBAC)
    const headers = await rbacHeaders();

    const response = await fetchWithTimeout(form.action, {
      method: "PUT",
      headers: {
        ...headers,
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
      },
      body: JSON.stringify(payload),
    });

    const { message } = await readBackendMessage(response);

    if (!response.ok) {
      throw new Error(message || `Failed to edit tool (HTTP ${response.status})`);
    }

    // Success -> redirect like your original behavior
    const searchParams = new URLSearchParams();
    if (isInactiveCheckedBool) searchParams.set("include_inactive", "true");
    if (teamId) searchParams.set("team_id", teamId);

    const queryString = searchParams.toString();
    const redirectUrl = `${window.ROOT_PATH}/admin${queryString ? `?${queryString}` : ""}#tools`;
    window.location.href = redirectUrl;
  } catch (error) {
    console.error("Fetch error:", error);
    showErrorMessage(error?.message || "Failed to edit tool");
  }
}

async function handleEditGatewayFormSubmit(e) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);
    try {
        // Validate form inputs
        const name = formData.get("name");
        const url = formData.get("url");

        const nameValidation = validateInputName(name, "gateway");
        const urlValidation = validateUrl(url);

        if (!nameValidation.valid) {
            throw new Error(nameValidation.error);
        }

        if (!urlValidation.valid) {
            throw new Error(urlValidation.error);
        }

        // Handle passthrough headers
        const passthroughHeadersString =
            formData.get("passthrough_headers") || "";
        const passthroughHeaders = passthroughHeadersString
            .split(",")
            .map((header) => header.trim())
            .filter((header) => header.length > 0);

        // Validate each header name
        for (const headerName of passthroughHeaders) {
            if (headerName && !HEADER_NAME_REGEX.test(headerName)) {
                showErrorMessage(
                    `Invalid passthrough header name: "${headerName}". Only letters, numbers, and hyphens are allowed.`,
                );
                return;
            }
        }

        formData.append(
            "passthrough_headers",
            JSON.stringify(passthroughHeaders),
        );

        // Handle OAuth configuration
        const authType = formData.get("auth_type");
        if (authType === "oauth") {
            const oauthConfig = {
                grant_type: formData.get("oauth_grant_type"),
                client_id: formData.get("oauth_client_id"),
                client_secret: formData.get("oauth_client_secret"),
                token_url: formData.get("oauth_token_url"),
                scopes: formData.get("oauth_scopes")
                    ? formData
                          .get("oauth_scopes")
                          .split(" ")
                          .filter((s) => s.trim())
                    : [],
            };

            // Add authorization code specific fields
            if (oauthConfig.grant_type === "authorization_code") {
                oauthConfig.authorization_url = formData.get(
                    "oauth_authorization_url",
                );
                oauthConfig.redirect_uri = formData.get("oauth_redirect_uri");
            }

            // Remove individual OAuth fields and add as oauth_config
            formData.delete("oauth_grant_type");
            formData.delete("oauth_client_id");
            formData.delete("oauth_client_secret");
            formData.delete("oauth_token_url");
            formData.delete("oauth_scopes");
            formData.delete("oauth_authorization_url");
            formData.delete("oauth_redirect_uri");

            formData.append("oauth_config", JSON.stringify(oauthConfig));
        }

        const isInactiveCheckedBool = isInactiveChecked("gateways");
        formData.append("is_inactive_checked", isInactiveCheckedBool);
        // Submit via fetch
        const response = await fetch(form.action, {
            method: "POST",
            body: formData,
        });
        const result = await response.json();
        if (!result || !result.success) {
            throw new Error(result?.message || "Failed to edit gateway");
        }
        // Only redirect on success
        const teamId = new URL(window.location.href).searchParams.get(
            "team_id",
        );

        const searchParams = new URLSearchParams();
        if (isInactiveCheckedBool) {
            searchParams.set("include_inactive", "true");
        }
        if (teamId) {
            searchParams.set("team_id", teamId);
        }
        const queryString = searchParams.toString();
        const redirectUrl = `${window.ROOT_PATH}/admin${queryString ? `?${queryString}` : ""}#gateways`;
        window.location.href = redirectUrl;
    } catch (error) {
        console.error("Error:", error);
        showErrorMessage(error.message);
    }
}

async function handleEditServerFormSubmit(e) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);

    try {
        // Validate inputs
        const name = formData.get("name");
        const nameValidation = validateInputName(name, "server");
        if (!nameValidation.valid) {
            throw new Error(nameValidation.error);
        }

        // Save CodeMirror editors' contents if present
        if (window.promptToolHeadersEditor) {
            window.promptToolHeadersEditor.save();
        }
        if (window.promptToolSchemaEditor) {
            window.promptToolSchemaEditor.save();
        }

        const isInactiveCheckedBool = isInactiveChecked("servers");
        formData.append("is_inactive_checked", isInactiveCheckedBool);

        // Submit via fetch
        const response = await fetch(form.action, {
            method: "POST",
            body: formData,
        });
        const result = await response.json();
        if (!result || !result.success) {
            throw new Error(result?.message || "Failed to edit server");
        }
        // Only redirect on success
        else {
            // Redirect to the appropriate page based on inactivity checkbox
            const teamId = new URL(window.location.href).searchParams.get(
                "team_id",
            );

            const searchParams = new URLSearchParams();
            if (isInactiveCheckedBool) {
                searchParams.set("include_inactive", "true");
            }
            if (teamId) {
                searchParams.set("team_id", teamId);
            }
            const queryString = searchParams.toString();
            const redirectUrl = `${window.ROOT_PATH}/admin${queryString ? `?${queryString}` : ""}#catalog`;
            window.location.href = redirectUrl;
        }
    } catch (error) {
        console.error("Error:", error);
        showErrorMessage(error.message);
    }
}

async function handleEditResFormSubmit(e) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);

    try {
        // Validate inputs
        const name = formData.get("name");
        const uri = formData.get("uri");
        const nameValidation = validateInputName(name, "resource");
        const uriValidation = validateInputName(uri, "resource URI");

        if (!nameValidation.valid) {
            showErrorMessage(nameValidation.error);
            return;
        }

        if (!uriValidation.valid) {
            showErrorMessage(uriValidation.error);
            return;
        }

        // Save CodeMirror editors' contents if present
        if (window.promptToolHeadersEditor) {
            window.promptToolHeadersEditor.save();
        }
        if (window.promptToolSchemaEditor) {
            window.promptToolSchemaEditor.save();
        }

        const isInactiveCheckedBool = isInactiveChecked("resources");
        formData.append("is_inactive_checked", isInactiveCheckedBool);
        // Submit via fetch
        const response = await fetch(form.action, {
            method: "POST",
            body: formData,
        });

        const result = await response.json();
        if (!result || !result.success) {
            throw new Error(result?.message || "Failed to edit resource");
        }
        // Only redirect on success
        else {
            // Redirect to the appropriate page based on inactivity checkbox
            const teamId = new URL(window.location.href).searchParams.get(
                "team_id",
            );

            const searchParams = new URLSearchParams();
            if (isInactiveCheckedBool) {
                searchParams.set("include_inactive", "true");
            }
            if (teamId) {
                searchParams.set("team_id", teamId);
            }
            const queryString = searchParams.toString();
            const redirectUrl = `${window.ROOT_PATH}/admin${queryString ? `?${queryString}` : ""}#resources`;
            window.location.href = redirectUrl;
        }
    } catch (error) {
        console.error("Error:", error);
        showErrorMessage(error.message);
    }
}

// ===================================================================
// ENHANCED FORM VALIDATION for All Forms
// ===================================================================

function setupFormValidation() {
    // Add validation to all forms on the page
    const forms = document.querySelectorAll("form");

    forms.forEach((form) => {
        // Add validation to name fields
        const nameFields = form.querySelectorAll(
            'input[name*="name"], input[name*="Name"]',
        );
        nameFields.forEach((field) => {
            field.addEventListener("blur", function () {
                const validation = validateInputName(this.value, "name");
                if (!validation.valid) {
                    this.setCustomValidity(validation.error);
                    this.reportValidity();
                } else {
                    this.setCustomValidity("");
                    this.value = validation.value;
                }
            });
        });

        // Add validation to URL fields
        const urlFields = form.querySelectorAll(
            'input[name*="url"], input[name*="URL"]',
        );
        urlFields.forEach((field) => {
            field.addEventListener("blur", function () {
                if (this.value) {
                    const validation = validateUrl(this.value);
                    if (!validation.valid) {
                        this.setCustomValidity(validation.error);
                        this.reportValidity();
                    } else {
                        this.setCustomValidity("");
                        this.value = validation.value;
                    }
                }
            });
        });

        // Special validation for prompt name fields
        const promptNameFields = form.querySelectorAll(
            'input[name="prompt-name"], input[name="edit-prompt-name"]',
        );
        promptNameFields.forEach((field) => {
            field.addEventListener("blur", function () {
                const validation = validateInputName(this.value, "prompt");
                if (!validation.valid) {
                    this.setCustomValidity(validation.error);
                    this.reportValidity();
                } else {
                    this.setCustomValidity("");
                    this.value = validation.value;
                }
            });
        });
    });
}

// ===================================================================
// ENHANCED EDITOR REFRESH with Safety Checks
// ===================================================================

function refreshEditors() {
    setTimeout(() => {
        if (
            window.headersEditor &&
            typeof window.headersEditor.refresh === "function"
        ) {
            try {
                window.headersEditor.refresh();
                console.log("✓ Refreshed headersEditor");
            } catch (error) {
                console.error("Failed to refresh headersEditor:", error);
            }
        }

        if (
            window.schemaEditor &&
            typeof window.schemaEditor.refresh === "function"
        ) {
            try {
                window.schemaEditor.refresh();
                console.log("✓ Refreshed schemaEditor");
            } catch (error) {
                console.error("Failed to refresh schemaEditor:", error);
            }
        }
    }, 100);
}

// ===================================================================
// GLOBAL ERROR HANDLERS
// ===================================================================

window.addEventListener("error", (e) => {
    console.error("Global error:", e.error, e.filename, e.lineno);
    // Don't show user error for every script error, just log it
});

window.addEventListener("unhandledrejection", (e) => {
    console.error("Unhandled promise rejection:", e.reason);
    // Show user error for unhandled promises as they're often more serious
    showErrorMessage("An unexpected error occurred. Please refresh the page.");
});

// Enhanced cleanup function for page unload
window.addEventListener("beforeunload", () => {
    try {
        AppState.reset();
        cleanupToolTestState(); // ADD THIS LINE
        console.log("✓ Application state cleaned up before unload");
    } catch (error) {
        console.error("Error during cleanup:", error);
    }
});

// Performance monitoring
if (window.performance && window.performance.mark) {
    window.performance.mark("app-security-complete");
    console.log("✓ Performance markers available");
}

// ===================================================================
// Tool Tips for components with Alpine.js
// ===================================================================

/* global Alpine */
function setupTooltipsWithAlpine() {
    document.addEventListener("alpine:init", () => {
        console.log("Initializing Alpine tooltip directive...");

        Alpine.directive("tooltip", (el, { expression }, { evaluate }) => {
            let tooltipEl = null;
            let animationFrameId = null; // Track animation frame

            const moveTooltip = (e) => {
                if (!tooltipEl) {
                    return;
                }

                const paddingX = 12;
                const paddingY = 20;
                const tipRect = tooltipEl.getBoundingClientRect();

                let left = e.clientX + paddingX;
                let top = e.clientY + paddingY;

                if (left + tipRect.width > window.innerWidth - 8) {
                    left = e.clientX - tipRect.width - paddingX;
                }
                if (top + tipRect.height > window.innerHeight - 8) {
                    top = e.clientY - tipRect.height - paddingY;
                }

                tooltipEl.style.left = `${left}px`;
                tooltipEl.style.top = `${top}px`;
            };

            const showTooltip = (event) => {
                const text = evaluate(expression);
                if (!text) {
                    return;
                }

                hideTooltip(); // Clean up any existing tooltip

                tooltipEl = document.createElement("div");
                tooltipEl.textContent = text;
                tooltipEl.setAttribute("role", "tooltip");
                tooltipEl.className =
                    "fixed z-50 max-w-xs px-3 py-2 text-sm text-white bg-black/80 rounded-lg shadow-lg pointer-events-none opacity-0 transition-opacity duration-200";

                document.body.appendChild(tooltipEl);

                if (event?.clientX && event?.clientY) {
                    moveTooltip(event);
                    el.addEventListener("mousemove", moveTooltip);
                } else {
                    const rect = el.getBoundingClientRect();
                    const scrollY = window.scrollY || window.pageYOffset;
                    const scrollX = window.scrollX || window.pageXOffset;
                    tooltipEl.style.left = `${rect.left + scrollX}px`;
                    tooltipEl.style.top = `${rect.bottom + scrollY + 10}px`;
                }

                // FIX: Cancel any pending animation frame before setting a new one
                if (animationFrameId) {
                    cancelAnimationFrame(animationFrameId);
                }

                animationFrameId = requestAnimationFrame(() => {
                    // FIX: Check if tooltipEl still exists before accessing its style
                    if (tooltipEl) {
                        tooltipEl.style.opacity = "1";
                    }
                    animationFrameId = null;
                });

                window.addEventListener("scroll", hideTooltip, {
                    passive: true,
                });
                window.addEventListener("resize", hideTooltip, {
                    passive: true,
                });
            };

            const hideTooltip = () => {
                if (!tooltipEl) {
                    return;
                }

                // FIX: Cancel any pending animation frame
                if (animationFrameId) {
                    cancelAnimationFrame(animationFrameId);
                    animationFrameId = null;
                }

                tooltipEl.style.opacity = "0";
                el.removeEventListener("mousemove", moveTooltip);
                window.removeEventListener("scroll", hideTooltip);
                window.removeEventListener("resize", hideTooltip);
                el.removeEventListener("click", hideTooltip);

                const toRemove = tooltipEl;
                tooltipEl = null; // Set to null immediately

                setTimeout(() => {
                    if (toRemove && toRemove.parentNode) {
                        toRemove.parentNode.removeChild(toRemove);
                    }
                }, 200);
            };

            el.addEventListener("mouseenter", showTooltip);
            el.addEventListener("mouseleave", hideTooltip);
            el.addEventListener("focus", showTooltip);
            el.addEventListener("blur", hideTooltip);
            el.addEventListener("click", hideTooltip);
        });
    });
}

setupTooltipsWithAlpine();

// ===================================================================
// SINGLE CONSOLIDATED INITIALIZATION SYSTEM
// ===================================================================

document.addEventListener("DOMContentLoaded", () => {
    console.log("🔐 DOM loaded - initializing secure admin interface...");

    try {
        // initializeTooltips();

        // 1. Initialize CodeMirror editors first
        initializeCodeMirrorEditors();

        // 2. Initialize tool selects
        initializeToolSelects();

        // 3. Set up all event listeners
        initializeEventListeners();

        // 4. Handle initial tab/state
        initializeTabState();

        // 5. Set up form validation
        setupFormValidation();

        // 6. Setup bulk import modal
        try {
            setupBulkImportModal();
        } catch (error) {
            console.error("Error setting up bulk import modal:", error);
        }

        // 7. Initialize export/import functionality
        try {
            initializeExportImport();
        } catch (error) {
            console.error(
                "Error setting up export/import functionality:",
                error,
            );
        }

        // // ✅ 4.1 Set up tab button click handlers
        // document.querySelectorAll('.tab-button').forEach(button => {
        //     button.addEventListener('click', () => {
        //         const tabId = button.getAttribute('data-tab');

        //         document.querySelectorAll('.tab-panel').forEach(panel => {
        //             panel.classList.add('hidden');
        //         });

        //         document.getElementById(tabId).classList.remove('hidden');
        //     });
        // });

        // Mark as initialized
        AppState.isInitialized = true;

        console.log(
            "✅ Secure initialization complete - XSS protection active",
        );
    } catch (error) {
        console.error("❌ Initialization failed:", error);
        showErrorMessage(
            "Failed to initialize the application. Please refresh the page.",
        );
    }
});

// Separate initialization functions
function initializeCodeMirrorEditors() {
    console.log("Initializing CodeMirror editors...");

    const editorConfigs = [
        {
            id: "headers-editor",
            mode: "application/json",
            varName: "headersEditor",
        },
        {
            id: "schema-editor",
            mode: "application/json",
            varName: "schemaEditor",
        },
        {
            id: "resource-content-editor",
            mode: "text/plain",
            varName: "resourceContentEditor",
        },
        {
            id: "prompt-template-editor",
            mode: "text/plain",
            varName: "promptTemplateEditor",
        },
        {
            id: "prompt-args-editor",
            mode: "application/json",
            varName: "promptArgsEditor",
        },
        {
            id: "edit-tool-headers",
            mode: "application/json",
            varName: "editToolHeadersEditor",
        },
        {
            id: "edit-tool-schema",
            mode: "application/json",
            varName: "editToolSchemaEditor",
        },
        {
            id: "edit-resource-content",
            mode: "text/plain",
            varName: "editResourceContentEditor",
        },
        {
            id: "edit-prompt-template",
            mode: "text/plain",
            varName: "editPromptTemplateEditor",
        },
        {
            id: "edit-prompt-arguments",
            mode: "application/json",
            varName: "editPromptArgumentsEditor",
        },
    ];

    editorConfigs.forEach((config) => {
        const element = safeGetElement(config.id);
        if (element && window.CodeMirror) {
            try {
                window[config.varName] = window.CodeMirror.fromTextArea(
                    element,
                    {
                        mode: config.mode,
                        theme: "monokai",
                        lineNumbers: false,
                        autoCloseBrackets: true,
                        matchBrackets: true,
                        tabSize: 2,
                        lineWrapping: true,
                    },
                );
                console.log(`✓ Initialized ${config.varName}`);
            } catch (error) {
                console.error(`Failed to initialize ${config.varName}:`, error);
            }
        } else {
            console.warn(
                `Element ${config.id} not found or CodeMirror not available`,
            );
        }
    });
}

function initializeToolSelects() {
    console.log("Initializing tool selects...");

    initToolSelect(
        "associatedTools",
        "selectedToolsPills",
        "selectedToolsWarning",
        6,
        "selectAllToolsBtn",
        "clearAllToolsBtn",
    );
    initToolSelect(
        "edit-server-tools",
        "selectedEditToolsPills",
        "selectedEditToolsWarning",
        6,
        "selectAllEditToolsBtn",
        "clearAllEditToolsBtn",
    );

    // Initialize resource selector
    initResourceSelect(
        "edit-server-resources",
        "selectedEditResourcesPills",
        "selectedEditResourcesWarning",
        10,
        "selectAllEditResourcesBtn",
        "clearAllEditResourcesBtn",
    );

    // Initialize prompt selector
    initPromptSelect(
        "edit-server-prompts",
        "selectedEditPromptsPills",
        "selectedEditPromptsWarning",
        8,
        "selectAllEditPromptsBtn",
        "clearAllEditPromptsBtn",
    );
}

function initializeEventListeners() {
    console.log("Setting up event listeners...");

    setupHeaderHomeNavigation();
    setupTabNavigation();
    setupHTMXHooks();
    setupAuthenticationToggles();
    setupFormHandlers();
    setupSchemaModeHandlers();
    setupIntegrationTypeHandlers();
}

function setupHeaderHomeNavigation() {
    const logoHomeBtn = safeGetElement("logo-home-button", true);
    if (!logoHomeBtn || logoHomeBtn.hasAttribute("data-setup")) {
        return;
    }

    logoHomeBtn.addEventListener("click", (event) => {
        event.preventDefault();
        showTab("gateways");
        if (window.history && typeof window.history.replaceState === "function") {
            window.history.replaceState(null, "", "#gateways");
        }
        window.scrollTo({ top: 0, behavior: "smooth" });
    });

    logoHomeBtn.setAttribute("data-setup", "true");
}

function setupTabNavigation() {
    const tabs = [
        "catalog",
        "tools",
        "resources",
        "prompts",
        "gateways",
        "teams",
        "a2a-agents",
        "roots",
        "metrics",
        "logs",
        "export-import",
        "version-info",
    ];

    tabs.forEach((tabName) => {
        // Suppress warnings for optional tabs that might not be enabled
        const optionalTabs = ["roots", "logs", "export-import", "version-info", "teams"];
        const suppressWarning = optionalTabs.includes(tabName);

        const tabElement = safeGetElement(`tab-${tabName}`, suppressWarning);
        if (tabElement) {
            tabElement.addEventListener("click", () => showTab(tabName));
        }
    });
}

function setupHTMXHooks() {
    document.body.addEventListener("htmx:beforeRequest", (event) => {
        if (event.detail.elt.id === "tab-version-info") {
            console.log("HTMX: Sending request for version info partial");
        }
    });

    document.body.addEventListener("htmx:afterSwap", (event) => {
        if (event.detail.target.id === "version-info-panel") {
            console.log("HTMX: Content swapped into version-info-panel");
        }
    });
}

function setupAuthenticationToggles() {
    const authHandlers = [
        {
            id: "auth-type",
            basicId: "auth-basic-fields",
            bearerId: "auth-bearer-fields",
            headersId: "auth-headers-fields",
        },
        {
            id: "auth-type-gw",
            basicId: "auth-basic-fields-gw",
            bearerId: "auth-bearer-fields-gw",
            headersId: "auth-headers-fields-gw",
        },
        {
            id: "auth-type-gw-edit",
            basicId: "auth-basic-fields-gw-edit",
            bearerId: "auth-bearer-fields-gw-edit",
            headersId: "auth-headers-fields-gw-edit",
            oauthId: "auth-oauth-fields-gw-edit",
        },
        {
            id: "edit-auth-type",
            basicId: "edit-auth-basic-fields",
            bearerId: "edit-auth-bearer-fields",
            headersId: "edit-auth-headers-fields",
        },
    ];

    authHandlers.forEach((handler) => {
        const element = safeGetElement(handler.id);
        if (element) {
            element.addEventListener("change", function () {
                const basicFields = safeGetElement(handler.basicId);
                const bearerFields = safeGetElement(handler.bearerId);
                const headersFields = safeGetElement(handler.headersId);
                handleAuthTypeSelection(
                    this.value,
                    basicFields,
                    bearerFields,
                    headersFields,
                );
            });
        }
    });
}

function setupFormHandlers() {
    const gatewayForm = safeGetElement("add-gateway-form");
    if (gatewayForm) {
        gatewayForm.addEventListener("submit", handleGatewayFormSubmit);

        // Add OAuth authentication type change handler
        const authTypeField = safeGetElement("auth-type-gw");
        if (authTypeField) {
            authTypeField.addEventListener("change", handleAuthTypeChange);
        }

        // Add OAuth grant type change handler
        const oauthGrantTypeField = safeGetElement("oauth-grant-type-gw");
        if (oauthGrantTypeField) {
            oauthGrantTypeField.addEventListener(
                "change",
                handleOAuthGrantTypeChange,
            );
        }
    }

    const resourceForm = safeGetElement("add-resource-form");
    if (resourceForm) {
        resourceForm.addEventListener("submit", handleResourceFormSubmit);
    }

    const promptForm = safeGetElement("add-prompt-form");
    if (promptForm) {
        promptForm.addEventListener("submit", handlePromptFormSubmit);
    }

    const editPromptForm = safeGetElement("edit-prompt-form");
    if (editPromptForm) {
        editPromptForm.addEventListener("submit", handleEditPromptFormSubmit);
        editPromptForm.addEventListener("click", () => {
            if (getComputedStyle(editPromptForm).display !== "none") {
                refreshEditors();
            }
        });
    }

    // Add OAuth grant type change handler for Edit Gateway modal
    const editOAuthGrantTypeField = safeGetElement("oauth-grant-type-gw-edit");
    if (editOAuthGrantTypeField) {
        editOAuthGrantTypeField.addEventListener(
            "change",
            handleEditOAuthGrantTypeChange,
        );
    }

    const toolForm = safeGetElement("add-tool-form");
    if (toolForm) {
        toolForm.addEventListener("submit", handleToolFormSubmit);
        toolForm.addEventListener("click", () => {
            if (getComputedStyle(toolForm).display !== "none") {
                refreshEditors();
            }
        });
    }

    const paramButton = safeGetElement("add-parameter-btn");
    if (paramButton) {
        paramButton.addEventListener("click", handleAddParameter);
    }

    const serverForm = safeGetElement("add-server-form");
    if (serverForm) {
        serverForm.addEventListener("submit", handleServerFormSubmit);
    }

    const editServerForm = safeGetElement("edit-server-form");
    if (editServerForm) {
        editServerForm.addEventListener("submit", handleEditServerFormSubmit);
        editServerForm.addEventListener("click", () => {
            if (getComputedStyle(editServerForm).display !== "none") {
                refreshEditors();
            }
        });
    }

    const editResourceForm = safeGetElement("edit-resource-form");
    if (editResourceForm) {
        editResourceForm.addEventListener("submit", handleEditResFormSubmit);
        editResourceForm.addEventListener("click", () => {
            if (getComputedStyle(editResourceForm).display !== "none") {
                refreshEditors();
            }
        });
    }

    const editToolForm = safeGetElement("edit-tool-form");
    if (editToolForm) {
        editToolForm.addEventListener("submit", handleEditToolFormSubmit);
        editToolForm.addEventListener("click", () => {
            if (getComputedStyle(editToolForm).display !== "none") {
                refreshEditors();
            }
        });
    }

    const editGatewayForm = safeGetElement("edit-gateway-form");
    if (editGatewayForm) {
        editGatewayForm.addEventListener("submit", handleEditGatewayFormSubmit);
        editGatewayForm.addEventListener("click", () => {
            if (getComputedStyle(editGatewayForm).display !== "none") {
                refreshEditors();
            }
        });
    }

    // Setup search functionality for selectors
    setupSelectorSearch();
}

/**
 * Setup search functionality for multi-select dropdowns
 */
function setupSelectorSearch() {
    // Tools search
    const searchTools = safeGetElement("searchTools", true);
    if (searchTools) {
        searchTools.addEventListener("input", function () {
            filterSelectorItems(
                this.value,
                "#associatedTools",
                ".tool-item",
                "noToolsMessage",
                "searchQuery",
            );
        });
    }

    // Resources search
    const searchResources = safeGetElement("searchResources", true);
    if (searchResources) {
        searchResources.addEventListener("input", function () {
            filterSelectorItems(
                this.value,
                "#associatedResources",
                ".resource-item",
                "noResourcesMessage",
                "searchResourcesQuery",
            );
        });
    }

    // Prompts search
    const searchPrompts = safeGetElement("searchPrompts", true);
    if (searchPrompts) {
        searchPrompts.addEventListener("input", function () {
            filterSelectorItems(
                this.value,
                "#associatedPrompts",
                ".prompt-item",
                "noPromptsMessage",
                "searchPromptsQuery",
            );
        });
    }
}

/**
 * Generic function to filter items in multi-select dropdowns with no results message
 */
function filterSelectorItems(
    searchText,
    containerSelector,
    itemSelector,
    noResultsId,
    searchQueryId,
) {
    const container = document.querySelector(containerSelector);
    if (!container) {
        return;
    }

    const items = container.querySelectorAll(itemSelector);
    const search = searchText.toLowerCase().trim();
    let hasVisibleItems = false;

    items.forEach((item) => {
        let textContent = "";

        // Get text from all text nodes within the item
        const textElements = item.querySelectorAll(
            "span, .text-xs, .font-medium",
        );
        textElements.forEach((el) => {
            textContent += " " + el.textContent;
        });

        // Also get direct text content
        textContent += " " + item.textContent;

        if (search === "" || textContent.toLowerCase().includes(search)) {
            item.style.display = "";
            hasVisibleItems = true;
        } else {
            item.style.display = "none";
        }
    });

    // Handle no results message
    const noResultsMessage = safeGetElement(noResultsId, true);
    const searchQuerySpan = safeGetElement(searchQueryId, true);

    if (search !== "" && !hasVisibleItems) {
        if (noResultsMessage) {
            noResultsMessage.style.display = "block";
        }
        if (searchQuerySpan) {
            searchQuerySpan.textContent = searchText;
        }
    } else {
        if (noResultsMessage) {
            noResultsMessage.style.display = "none";
        }
    }
}

/**
 * Filter server table rows based on search text
 */
function filterServerTable(searchText) {
    try {
        const tbody = document.querySelector(
            'tbody[data-testid="server-list"]',
        );
        if (!tbody) {
            console.warn("Server table not found");
            return;
        }

        const rows = tbody.querySelectorAll('tr[data-testid="server-item"]');
        const search = searchText.toLowerCase().trim();

        rows.forEach((row) => {
            let textContent = "";

            // Get text from all cells in the row
            const cells = row.querySelectorAll("td");
            cells.forEach((cell) => {
                textContent += " " + cell.textContent;
            });

            if (search === "" || textContent.toLowerCase().includes(search)) {
                row.style.display = "";
            } else {
                row.style.display = "none";
            }
        });
    } catch (error) {
        console.error("Error filtering server table:", error);
    }
}

// Make server search function available globally
window.filterServerTable = filterServerTable;

/**
 * Filter gateway cards based on search text
 */
function filterGatewayTable(searchText) {
    try {
        const cards = document.querySelectorAll("#gateways-panel .gw-card");
        if (!cards.length) {
            console.warn("Gateway cards not found");
            return;
        }

        const search = (searchText || "").toLowerCase().trim();
        cards.forEach((card) => {
            const textContent = (card.textContent || "").toLowerCase();
            card.style.display =
                search === "" || textContent.includes(search) ? "" : "none";
        });
    } catch (error) {
        console.error("Error filtering gateway cards:", error);
    }
}

// Make gateway search function available globally
window.filterGatewayTable = filterGatewayTable;

/**
 * Filter tool cards based on search text
 */
function filterToolCards(searchText) {
    try {
        const cards = document.querySelectorAll("#tools-panel .tool-card");
        if (!cards.length) {
            console.warn("Tool cards not found");
            return;
        }

        const search = (searchText || "").toLowerCase().trim();
        cards.forEach((card) => {
            const textContent = (card.textContent || "").toLowerCase();
            card.style.display =
                search === "" || textContent.includes(search) ? "" : "none";
        });
    } catch (error) {
        console.error("Error filtering tool cards:", error);
    }
}

// Make tools search function available globally
window.filterToolCards = filterToolCards;

function handleAuthTypeChange() {
    const authType = this.value;
    const basicFields = safeGetElement("auth-basic-fields-gw");
    const bearerFields = safeGetElement("auth-bearer-fields-gw");
    const headersFields = safeGetElement("auth-headers-fields-gw");
    const oauthFields = safeGetElement("auth-oauth-fields-gw");

    // Hide all auth sections first
    if (basicFields) {
        basicFields.style.display = "none";
    }
    if (bearerFields) {
        bearerFields.style.display = "none";
    }
    if (headersFields) {
        headersFields.style.display = "none";
    }
    if (oauthFields) {
        oauthFields.style.display = "none";
    }

    // Show the appropriate section
    switch (authType) {
        case "basic":
            if (basicFields) {
                basicFields.style.display = "block";
            }
            break;
        case "bearer":
            if (bearerFields) {
                bearerFields.style.display = "block";
            }
            break;
        case "authheaders":
            if (headersFields) {
                headersFields.style.display = "block";
            }
            break;
        case "oauth":
            if (oauthFields) {
                oauthFields.style.display = "block";
            }
            break;
        default:
            // No auth - keep everything hidden
            break;
    }
}

function handleOAuthGrantTypeChange() {
    const grantType = this.value;
    const authCodeFields = safeGetElement("oauth-auth-code-fields-gw");

    if (authCodeFields) {
        if (grantType === "authorization_code") {
            authCodeFields.style.display = "block";

            // Make authorization code specific fields required
            const requiredFields =
                authCodeFields.querySelectorAll('input[type="url"]');
            requiredFields.forEach((field) => {
                field.required = true;
            });

            // Show additional validation for required fields
            console.log(
                "Authorization Code flow selected - additional fields are now required",
            );
        } else {
            authCodeFields.style.display = "none";

            // Remove required validation for hidden fields
            const requiredFields =
                authCodeFields.querySelectorAll('input[type="url"]');
            requiredFields.forEach((field) => {
                field.required = false;
            });
        }
    }
}

function handleEditOAuthGrantTypeChange() {
    const grantType = this.value;
    const authCodeFields = safeGetElement("oauth-auth-code-fields-gw-edit");

    if (authCodeFields) {
        if (grantType === "authorization_code") {
            authCodeFields.style.display = "block";

            // Make authorization code specific fields required
            const requiredFields =
                authCodeFields.querySelectorAll('input[type="url"]');
            requiredFields.forEach((field) => {
                field.required = true;
            });

            // Show additional validation for required fields
            console.log(
                "Authorization Code flow selected - additional fields are now required",
            );
        } else {
            authCodeFields.style.display = "none";

            // Remove required validation for hidden fields
            const requiredFields =
                authCodeFields.querySelectorAll('input[type="url"]');
            requiredFields.forEach((field) => {
                field.required = false;
            });
        }
    }
}

function setupSchemaModeHandlers() {
    const schemaModeRadios = document.getElementsByName("schema_input_mode");
    const uiBuilderDiv = safeGetElement("ui-builder");
    const jsonInputContainer = safeGetElement("json-input-container");

    if (schemaModeRadios.length === 0) {
        console.warn("Schema mode radios not found");
        return;
    }

    Array.from(schemaModeRadios).forEach((radio) => {
        radio.addEventListener("change", () => {
            try {
                if (radio.value === "ui" && radio.checked) {
                    if (uiBuilderDiv) {
                        uiBuilderDiv.style.display = "block";
                    }
                    if (jsonInputContainer) {
                        jsonInputContainer.style.display = "none";
                    }
                } else if (radio.value === "json" && radio.checked) {
                    if (uiBuilderDiv) {
                        uiBuilderDiv.style.display = "none";
                    }
                    if (jsonInputContainer) {
                        jsonInputContainer.style.display = "block";
                    }
                    updateSchemaPreview();
                }
            } catch (error) {
                console.error("Error handling schema mode change:", error);
            }
        });
    });

    console.log("✓ Schema mode handlers set up successfully");
}

function setupIntegrationTypeHandlers() {
    const integrationTypeSelect = safeGetElement("integrationType");
    if (integrationTypeSelect) {
        const defaultIntegration =
            integrationTypeSelect.dataset.default ||
            integrationTypeSelect.options[0].value;
        integrationTypeSelect.value = defaultIntegration;
        updateRequestTypeOptions();
        integrationTypeSelect.addEventListener("change", () =>
            updateRequestTypeOptions(),
        );
    }

    const editToolTypeSelect = safeGetElement("edit-tool-type");
    if (editToolTypeSelect) {
        editToolTypeSelect.addEventListener(
            "change",
            () => updateEditToolRequestTypes(),
            // updateEditToolUrl(),
        );
    }
}

function initializeTabState() {
    console.log("Initializing tab state...");

    const hash = window.location.hash;
    if (hash) {
        showTab(hash.slice(1));
    } else {
        showTab("catalog");
    }

    // Pre-load version info if that's the initial tab
    if (window.location.hash === "#version-info") {
        setTimeout(() => {
            const panel = safeGetElement("version-info-panel");
            if (panel && panel.innerHTML.trim() === "") {
                fetchWithTimeout(`${window.ROOT_PATH}/version?partial=true`)
                    .then((resp) => {
                        if (!resp.ok) {
                            throw new Error("Network response was not ok");
                        }
                        return resp.text();
                    })
                    .then((html) => {
                        safeSetInnerHTML(panel, html, true);
                    })
                    .catch((err) => {
                        console.error("Failed to preload version info:", err);
                        const errorDiv = document.createElement("div");
                        errorDiv.className = "text-red-600 p-4";
                        errorDiv.textContent = "Failed to load version info.";
                        panel.innerHTML = "";
                        panel.appendChild(errorDiv);
                    });
            }
        }, 100);
    }

    // Set checkbox states based on URL parameter
    const urlParams = new URLSearchParams(window.location.search);
    const includeInactive = urlParams.get("include_inactive") === "true";

    const checkboxes = [
        "show-inactive-tools",
        "show-inactive-resources",
        "show-inactive-prompts",
        "show-inactive-gateways",
        "show-inactive-servers",
    ];
    checkboxes.forEach((id) => {
        const checkbox = safeGetElement(id);
        if (checkbox) {
            checkbox.checked = includeInactive;
        }
    });
}

// ===================================================================
// GLOBAL EXPORTS - Make functions available to HTML onclick handlers
// ===================================================================

window.toggleInactiveItems = toggleInactiveItems;
window.handleToggleSubmit = handleToggleSubmit;
window.handleSubmitWithConfirmation = handleSubmitWithConfirmation;
window.viewTool = viewTool;
window.editTool = editTool;
window.testTool = testTool;
window.viewResource = viewResource;
window.editResource = editResource;
window.viewPrompt = viewPrompt;
window.editPrompt = editPrompt;
window.viewGateway = viewGateway;
window.editGateway = editGateway;
window.viewServer = viewServer;
window.editServer = editServer;
window.runToolTest = runToolTest;
window.testPrompt = testPrompt;
window.runPromptTest = runPromptTest;
window.closeModal = closeModal;
window.testGateway = testGateway;

// ===============================================
// CONFIG EXPORT FUNCTIONALITY
// ===============================================

/**
 * Global variables to store current config data
 *
 * NOTE:
 * We store this state on `window` (global) to avoid "Temporal Dead Zone" errors like:
 * "Cannot access 'currentServerId' before initialization"
 * which can happen if `let/const currentServerId` is shadowed/redeclared elsewhere in admin.js.
 */
window.currentConfigData = window.currentConfigData ?? null;
window.currentConfigType = window.currentConfigType ?? null;
window.currentServerName = window.currentServerName ?? null;
window.currentServerId = window.currentServerId ?? null;

/**
 * Show the config selection modal
 * @param {string} serverId - The server UUID
 * @param {string} serverName - The server name
 */
function showConfigSelectionModal(serverId, serverName) {
  // Store selected server info globally for later steps
  window.currentServerId = serverId;
  window.currentServerName = serverName;

  const serverNameDisplay = safeGetElement("server-name-display");
  if (serverNameDisplay) {
    serverNameDisplay.textContent = serverName;
  }

  openModal("config-selection-modal");
}
/**
 * Build MCP_SERVER_CATALOG_URL for a given server
 * @param {Object} server
 * @returns {string}
 */
function getCatalogUrl(server) {
  const currentHost = window.location.hostname;
  const currentPort =
    window.location.port ||
    (window.location.protocol === "https:" ? "443" : "80");
  const protocol = window.location.protocol;

  const baseUrl = `${protocol}//${currentHost}${
    currentPort !== "80" && currentPort !== "443" ? ":" + currentPort : ""
  }`;

  return `${baseUrl}/servers/${server.id}`;
}

/**
 * Generate and show configuration for selected type
 * @param {string} configType - Configuration type: 'stdio', 'sse', or 'http'
 */
async function generateAndShowConfig(configType) {
  try {
    console.log(
      `Generating ${configType} config for server ${window.currentServerId}`,
    );

    // Guard: must have a selected server
    if (!window.currentServerId) {
      showErrorMessage("No server selected. Please open a server and try again.");
      return;
    }

    // First, fetch the server details
    const response = await fetchWithTimeout(
      `${window.ROOT_PATH}/servers/${window.currentServerId}`,
    );

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const server = await response.json();

    // Generate the configuration
    const config = generateConfig(server, configType);

    // Store data for modal
    window.currentConfigData = config;
    window.currentConfigType = configType;

    // Close selection modal and show config display modal
    closeModal("config-selection-modal");
    showConfigDisplayModal(server, configType, config);

    console.log("✓ Config generated successfully");
  } catch (error) {
    console.error("Error generating config:", error);
    const errorMessage = handleFetchError(error, "generate configuration");
    showErrorMessage(errorMessage);
  }
}

/**
 * Export server configuration in specified format
 * @param {string} serverId - The server UUID
 * @param {string} configType - Configuration type: 'stdio', 'sse', or 'http'
 */
async function exportServerConfig(serverId, configType) {
  try {
    console.log(`Exporting ${configType} config for server ${serverId}`);

    // First, fetch the server details
    const response = await fetchWithTimeout(
      `${window.ROOT_PATH}/servers/${serverId}`,
    );

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const server = await response.json();

    // Generate the configuration
    const config = generateConfig(server, configType);

    // Store data for modal
    window.currentConfigData = config;
    window.currentConfigType = configType;
    window.currentServerName = server.name;

    // Show the modal with the config
    showConfigDisplayModal(server, configType, config);

    console.log("✓ Config generated successfully");
  } catch (error) {
    console.error("Error generating config:", error);
    const errorMessage = handleFetchError(error, "generate configuration");
    showErrorMessage(errorMessage);
  }
}

/**
 * Generate configuration object based on server and type
 * @param {Object} server - Server object from API
 * @param {string} configType - Configuration type
 * @returns {Object} - Generated configuration object
 */
function generateConfig(server, configType) {
  const currentHost = window.location.hostname;
  const currentPort =
    window.location.port ||
    (window.location.protocol === "https:" ? "443" : "80");
  const protocol = window.location.protocol;
  const baseUrl = `${protocol}//${currentHost}${
    currentPort !== "80" && currentPort !== "443" ? ":" + currentPort : ""
  }`;

  // Clean server name for use as config key (alphanumeric and hyphens only)
  const cleanServerName = server.name
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");

  switch (configType) {
    case "stdio":
      return {
        mcpServers: {
          "mcpgateway-wrapper": {
            command: "python",
            args: ["-m", "mcpgateway.wrapper"],
            env: {
              MCP_AUTH: "Bearer <your-token-here>",
              MCP_SERVER_URL: `${baseUrl}/servers/${server.id}`,
              MCP_TOOL_CALL_TIMEOUT: "120",
            },
          },
        },
      };

    case "sse":
      return {
        servers: {
          [cleanServerName]: {
            type: "sse",
            url: `${baseUrl}/servers/${server.id}/sse`,
            headers: {
              Authorization: "Bearer your-token-here",
            },
          },
        },
      };

    case "http":
      return {
        servers: {
          [cleanServerName]: {
            type: "http",
            url: `${baseUrl}/servers/${server.id}/mcp`,
            headers: {
              Authorization: "Bearer your-token-here",
            },
          },
        },
      };

    default:
      throw new Error(`Unknown config type: ${configType}`);
  }
}

/**
 * Show the config display modal with generated configuration
 * @param {Object} server - Server object
 * @param {string} configType - Configuration type
 * @param {Object} config - Generated configuration
 */
function showConfigDisplayModal(server, configType, config) {
  const descriptions = {
    stdio: "Configuration for Claude Desktop, CLI tools, and stdio-based MCP clients",
    sse: "Configuration for LangChain, LlamaIndex, and other SSE-based frameworks",
    http: "Configuration for REST clients and HTTP-based MCP integrations",
  };

  const usageInstructions = {
    stdio: "Save as .mcp.json in your user directory or use in Claude Desktop settings",
    sse: "Use with MCP client libraries that support Server-Sent Events transport",
    http: "Use with HTTP clients or REST API wrappers for MCP protocol",
  };

  // Update modal content
  const descriptionEl = safeGetElement("config-description");
  const usageEl = safeGetElement("config-usage");
  const contentEl = safeGetElement("config-content");

  if (descriptionEl) {
    descriptionEl.textContent = `${descriptions[configType]} for server "${server.name}"`;
  }

  if (usageEl) {
    usageEl.textContent = usageInstructions[configType];
  }

  if (contentEl) {
    contentEl.value = JSON.stringify(config, null, 2);
  }

  // Update title and open the modal
  const titleEl = safeGetElement("config-display-title");
  if (titleEl) {
    titleEl.textContent = `${configType.toUpperCase()} Configuration for ${server.name}`;
  }
  openModal("config-display-modal");
}

/**
 * Copy configuration to clipboard
 *
 * NOTE:
 * `navigator.clipboard` is only available in secure contexts (HTTPS or localhost),
 * and may be blocked by browser policies. So we use a safe fallback that works on HTTP too.
 */
async function copyConfigToClipboard() {
  const contentEl = safeGetElement("config-content");
  if (!contentEl) {
    showErrorMessage("Config content not found");
    return;
  }

  const textToCopy = contentEl.value || "";

  try {
    // Prefer modern Clipboard API when available
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      await navigator.clipboard.writeText(textToCopy);
      showSuccessMessage("Configuration copied to clipboard!");
      return;
    }

    // Fallback for HTTP / insecure contexts / older browsers:
    // Use a temporary textarea + document.execCommand('copy')
    const temp = document.createElement("textarea");
    temp.value = textToCopy;
    temp.setAttribute("readonly", "");
    temp.style.position = "fixed";
    temp.style.left = "-9999px";
    temp.style.top = "0";
    document.body.appendChild(temp);

    temp.focus();
    temp.select();

    const success = document.execCommand("copy");
    document.body.removeChild(temp);

    if (success) {
      showSuccessMessage("Configuration copied to clipboard!");
    } else {
      // Final fallback: select in the visible textarea for manual copy
      contentEl.focus();
      contentEl.select();
      contentEl.setSelectionRange(0, 99999);
      showErrorMessage("Clipboard blocked. Please copy the selected text manually (Ctrl+C).");
    }
  } catch (error) {
    console.error("Error copying to clipboard:", error);

    // Final fallback: select the text for manual copying
    contentEl.focus();
    contentEl.select();
    contentEl.setSelectionRange(0, 99999); // For mobile devices
    showErrorMessage("Clipboard blocked. Please copy the selected text manually (Ctrl+C).");
  }
}

/**
 * Download configuration as JSON file
 */
function downloadConfig() {
  if (!window.currentConfigData || !window.currentConfigType || !window.currentServerName) {
    showErrorMessage("No configuration data available");
    return;
  }

  try {
    const content = JSON.stringify(window.currentConfigData, null, 2);
    const blob = new Blob([content], { type: "application/json" });
    const url = window.URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = `${window.currentServerName}-${window.currentConfigType}-config.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);

    showSuccessMessage(`Configuration downloaded as ${a.download}`);
  } catch (error) {
    console.error("Error downloading config:", error);
    showErrorMessage("Failed to download configuration");
  }
}

/**
 * Go back to config selection modal
 */
function goBackToSelection() {
  closeModal("config-display-modal");
  openModal("config-selection-modal");
}

// Export functions to global scope immediately after definition
window.showConfigSelectionModal = showConfigSelectionModal;
window.generateAndShowConfig = generateAndShowConfig;
window.exportServerConfig = exportServerConfig;
window.copyConfigToClipboard = copyConfigToClipboard;
window.downloadConfig = downloadConfig;
window.goBackToSelection = goBackToSelection;



// ===============================================
// TAG FILTERING FUNCTIONALITY
// ===============================================

/**
 * Extract all unique tags from entities in a given entity type
 * @param {string} entityType - The entity type (tools, resources, prompts, servers, gateways)
 * @returns {Array<string>} - Array of unique tags
 */
function extractAvailableTags(entityType) {
    const tags = new Set();
    const tableSelector = `#${entityType}-panel tbody tr:not(.inactive-row)`;
    const rows = document.querySelectorAll(tableSelector);

    console.log(
        `[DEBUG] extractAvailableTags for ${entityType}: Found ${rows.length} rows`,
    );

    // Find the Tags column index by examining the table header
    const tableHeaderSelector = `#${entityType}-panel thead tr th`;
    const headerCells = document.querySelectorAll(tableHeaderSelector);
    let tagsColumnIndex = -1;

    headerCells.forEach((header, index) => {
        const headerText = header.textContent.trim().toLowerCase();
        if (headerText === "tags") {
            tagsColumnIndex = index;
            console.log(
                `[DEBUG] Found Tags column at index ${index} for ${entityType}`,
            );
        }
    });

    if (tagsColumnIndex === -1) {
        console.log(`[DEBUG] Could not find Tags column for ${entityType}`);
        return [];
    }

    rows.forEach((row, index) => {
        const cells = row.querySelectorAll("td");

        if (tagsColumnIndex < cells.length) {
            const tagsCell = cells[tagsColumnIndex];

            // Look for tag badges ONLY within the Tags column
            const tagElements = tagsCell.querySelectorAll(`
                span.inline-flex.items-center.px-2.py-0\\.5.rounded.text-xs.font-medium.bg-blue-100.text-blue-800,
                span.inline-block.bg-blue-100.text-blue-800.text-xs.px-2.py-1.rounded-full
            `);

            console.log(
                `[DEBUG] Row ${index}: Found ${tagElements.length} tag elements in Tags column`,
            );

            tagElements.forEach((tagEl) => {
                const tagText = tagEl.textContent.trim();
                console.log(
                    `[DEBUG] Row ${index}: Tag element text: "${tagText}"`,
                );

                // Basic validation for tag content
                if (
                    tagText &&
                    tagText !== "No tags" &&
                    tagText !== "None" &&
                    tagText !== "N/A" &&
                    tagText.length >= 2 &&
                    tagText.length <= 50
                ) {
                    tags.add(tagText);
                    console.log(
                        `[DEBUG] Row ${index}: Added tag: "${tagText}"`,
                    );
                } else {
                    console.log(
                        `[DEBUG] Row ${index}: Filtered out: "${tagText}"`,
                    );
                }
            });
        }
    });

    const result = Array.from(tags).sort();
    console.log(
        `[DEBUG] extractAvailableTags for ${entityType}: Final result:`,
        result,
    );
    return result;
}

/**
 * Update the available tags display for an entity type
 * @param {string} entityType - The entity type
 */
function updateAvailableTags(entityType) {
    const availableTagsContainer = document.getElementById(
        `${entityType}-available-tags`,
    );
    if (!availableTagsContainer) {
        return;
    }

    const tags = extractAvailableTags(entityType);
    availableTagsContainer.innerHTML = "";

    if (tags.length === 0) {
        availableTagsContainer.innerHTML =
            '<span class="text-sm text-gray-500">No tags found</span>';
        return;
    }

    tags.forEach((tag) => {
        const tagButton = document.createElement("button");
        tagButton.type = "button";
        tagButton.className =
            "inline-flex items-center px-2 py-1 text-xs font-medium rounded-full text-blue-700 bg-blue-100 hover:bg-blue-200 cursor-pointer";
        tagButton.textContent = tag;
        tagButton.title = `Click to filter by "${tag}"`;
        tagButton.onclick = () => addTagToFilter(entityType, tag);
        availableTagsContainer.appendChild(tagButton);
    });
}

/**
 * Add a tag to the filter input
 * @param {string} entityType - The entity type
 * @param {string} tag - The tag to add
 */
function addTagToFilter(entityType, tag) {
    const filterInput = document.getElementById(`${entityType}-tag-filter`);
    if (!filterInput) {
        return;
    }

    const currentTags = filterInput.value
        .split(",")
        .map((t) => t.trim())
        .filter((t) => t);
    if (!currentTags.includes(tag)) {
        currentTags.push(tag);
        filterInput.value = currentTags.join(", ");
        filterEntitiesByTags(entityType, filterInput.value);
    }
}

/**
 * Filter entities by tags
 * @param {string} entityType - The entity type (tools, resources, prompts, servers, gateways)
 * @param {string} tagsInput - Comma-separated string of tags to filter by
 */
function filterEntitiesByTags(entityType, tagsInput) {
    const filterTags = tagsInput
        .split(",")
        .map((tag) => tag.trim().toLowerCase())
        .filter((tag) => tag);
    const tableSelector = `#${entityType}-panel tbody tr`;
    const rows = document.querySelectorAll(tableSelector);

    let visibleCount = 0;

    rows.forEach((row) => {
        if (filterTags.length === 0) {
            // Show all rows when no filter is applied
            row.style.display = "";
            visibleCount++;
            return;
        }

        // Extract tags from this row using specific tag selectors (not status badges)
        const rowTags = new Set();
        const tagElements = row.querySelectorAll(`
            span.inline-flex.items-center.px-2.py-0\\.5.rounded.text-xs.font-medium.bg-blue-100.text-blue-800,
            span.inline-block.bg-blue-100.text-blue-800.text-xs.px-2.py-1.rounded-full
        `);
        tagElements.forEach((tagEl) => {
            const tagText = tagEl.textContent.trim().toLowerCase();
            // Filter out any remaining non-tag content
            if (
                tagText &&
                tagText !== "no tags" &&
                tagText !== "none" &&
                tagText !== "active" &&
                tagText !== "inactive" &&
                tagText !== "online" &&
                tagText !== "offline"
            ) {
                rowTags.add(tagText);
            }
        });

        // Check if any of the filter tags match any of the row tags (OR logic)
        const hasMatchingTag = filterTags.some((filterTag) =>
            Array.from(rowTags).some(
                (rowTag) =>
                    rowTag.includes(filterTag) || filterTag.includes(rowTag),
            ),
        );

        if (hasMatchingTag) {
            row.style.display = "";
            visibleCount++;
        } else {
            row.style.display = "none";
        }
    });

    // Update empty state message
    updateFilterEmptyState(entityType, visibleCount, filterTags.length > 0);
}

/**
 * Update empty state message when filtering
 * @param {string} entityType - The entity type
 * @param {number} visibleCount - Number of visible entities
 * @param {boolean} isFiltering - Whether filtering is active
 */
function updateFilterEmptyState(entityType, visibleCount, isFiltering) {
    const tableContainer = document.querySelector(
        `#${entityType}-panel .overflow-x-auto`,
    );
    if (!tableContainer) {
        return;
    }

    let emptyMessage = tableContainer.querySelector(
        ".tag-filter-empty-message",
    );

    if (visibleCount === 0 && isFiltering) {
        if (!emptyMessage) {
            emptyMessage = document.createElement("div");
            emptyMessage.className =
                "tag-filter-empty-message text-center py-8 text-gray-500";
            emptyMessage.innerHTML = `
                <div class="flex flex-col items-center">
                    <svg class="w-12 h-12 text-gray-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                    </svg>
                    <h3 class="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">No matching ${entityType}</h3>
                    <p class="text-gray-500 dark:text-gray-400">No ${entityType} found with the specified tags. Try adjusting your filter or <button onclick="clearTagFilter('${entityType}')" class="figma-blue-txt hover:figma-blue-txt underline">clear the filter</button>.</p>
                </div>
            `;
            tableContainer.appendChild(emptyMessage);
        }
        emptyMessage.style.display = "block";
    } else if (emptyMessage) {
        emptyMessage.style.display = "none";
    }
}

/**
 * Clear the tag filter for an entity type
 * @param {string} entityType - The entity type
 */
function clearTagFilter(entityType) {
    const filterInput = document.getElementById(`${entityType}-tag-filter`);
    if (filterInput) {
        filterInput.value = "";
        filterEntitiesByTags(entityType, "");
    }
}

/**
 * Initialize tag filtering for all entity types on page load
 */
function initializeTagFiltering() {
    const entityTypes = [
        "catalog",
        "tools",
        "resources",
        "prompts",
        "servers",
        "gateways",
    ];

    entityTypes.forEach((entityType) => {
        // Update available tags on page load
        updateAvailableTags(entityType);

        // Set up event listeners for tab switching to refresh tags
        const tabButton = document.getElementById(`tab-${entityType}`);
        if (tabButton) {
            tabButton.addEventListener("click", () => {
                // Delay to ensure tab content is visible
                setTimeout(() => updateAvailableTags(entityType), 100);
            });
        }
    });
}

// Initialize tag filtering when page loads
document.addEventListener("DOMContentLoaded", function () {
    initializeTagFiltering();
});

// Expose tag filtering functions to global scope
window.filterEntitiesByTags = filterEntitiesByTags;
window.clearTagFilter = clearTagFilter;
window.updateAvailableTags = updateAvailableTags;

// ===================================================================
// MULTI-HEADER AUTHENTICATION MANAGEMENT
// ===================================================================

/**
 * Global counter for unique header IDs
 */
let headerCounter = 0;

/**
 * Add a new authentication header row to the specified container
 * @param {string} containerId - ID of the container to add the header row to
 */
function addAuthHeader(containerId) {
    const container = document.getElementById(containerId);
    if (!container) {
        console.error(`Container with ID ${containerId} not found`);
        return;
    }

    const headerId = `auth-header-${++headerCounter}`;

    const headerRow = document.createElement("div");
    headerRow.className = "flex items-center space-x-2";
    headerRow.id = headerId;

    headerRow.innerHTML = `
        <div class="flex-1">
            <input
                type="text"
                placeholder="Header Key (e.g., X-API-Key)"
                class="auth-header-key block w-full rounded-md border border-gray-300 dark:border-gray-700 shadow-sm focus:figma-blue-border focus:ring-indigo-500 dark:bg-gray-900 dark:placeholder-gray-300 dark:text-gray-300 text-sm"
                oninput="updateAuthHeadersJSON('${containerId}')"
            />
        </div>
        <div class="flex-1">
            <input
                type="password"
                placeholder="Header Value"
                class="auth-header-value block w-full rounded-md border border-gray-300 dark:border-gray-700 shadow-sm focus:figma-blue-border focus:ring-indigo-500 dark:bg-gray-900 dark:placeholder-gray-300 dark:text-gray-300 text-sm"
                oninput="updateAuthHeadersJSON('${containerId}')"
            />
        </div>
        <button
            type="button"
            onclick="removeAuthHeader('${headerId}', '${containerId}')"
            class="inline-flex items-center px-2 py-1 border border-transparent text-sm leading-4 font-medium rounded-md text-red-700 bg-red-100 hover:bg-red-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 dark:bg-red-900 dark:text-red-300 dark:hover:bg-red-800"
            title="Remove header"
        >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
            </svg>
        </button>
    `;

    container.appendChild(headerRow);
    updateAuthHeadersJSON(containerId);

    // Focus on the key input of the new header
    const keyInput = headerRow.querySelector(".auth-header-key");
    if (keyInput) {
        keyInput.focus();
    }
}

/**
 * Remove an authentication header row
 * @param {string} headerId - ID of the header row to remove
 * @param {string} containerId - ID of the container to update
 */
function removeAuthHeader(headerId, containerId) {
    const headerRow = document.getElementById(headerId);
    if (headerRow) {
        headerRow.remove();
        updateAuthHeadersJSON(containerId);
    }
}

/**
 * Update the JSON representation of authentication headers
 * @param {string} containerId - ID of the container with headers
 */
function updateAuthHeadersJSON(containerId) {
    const container = document.getElementById(containerId);
    if (!container) {
        return;
    }

    const headers = [];
    const headerRows = container.querySelectorAll('[id^="auth-header-"]');
    const duplicateKeys = new Set();
    const seenKeys = new Set();
    let hasValidationErrors = false;

    headerRows.forEach((row) => {
        const keyInput = row.querySelector(".auth-header-key");
        const valueInput = row.querySelector(".auth-header-value");

        if (keyInput && valueInput) {
            const key = keyInput.value.trim();
            const value = valueInput.value.trim();

            // Skip completely empty rows
            if (!key && !value) {
                return;
            }

            // Require key but allow empty values
            if (!key) {
                keyInput.setCustomValidity("Header key is required");
                keyInput.reportValidity();
                hasValidationErrors = true;
                return;
            }

            // Validate header key format (letters, numbers, hyphens, underscores)
            if (!/^[a-zA-Z0-9\-_]+$/.test(key)) {
                keyInput.setCustomValidity(
                    "Header keys should contain only letters, numbers, hyphens, and underscores",
                );
                keyInput.reportValidity();
                hasValidationErrors = true;
                return;
            } else {
                keyInput.setCustomValidity("");
            }

            // Track duplicate keys
            if (seenKeys.has(key.toLowerCase())) {
                duplicateKeys.add(key);
            }
            seenKeys.add(key.toLowerCase());

            headers.push({
                key,
                value, // Allow empty values
            });
        }
    });

    // Find the corresponding JSON input field
    let jsonInput = null;
    if (containerId === "auth-headers-container") {
        jsonInput = document.getElementById("auth-headers-json");
    } else if (containerId === "auth-headers-container-gw") {
        jsonInput = document.getElementById("auth-headers-json-gw");
    } else if (containerId === "edit-auth-headers-container") {
        jsonInput = document.getElementById("edit-auth-headers-json");
    } else if (containerId === "auth-headers-container-gw-edit") {
        jsonInput = document.getElementById("auth-headers-json-gw-edit");
    }

    // Warn about duplicate keys in console
    if (duplicateKeys.size > 0 && !hasValidationErrors) {
        console.warn(
            "Duplicate header keys detected (last value will be used):",
            Array.from(duplicateKeys),
        );
    }

    // Check for excessive headers
    if (headers.length > 100) {
        console.error("Maximum of 100 headers allowed per gateway");
        return;
    }

    if (jsonInput) {
        jsonInput.value = headers.length > 0 ? JSON.stringify(headers) : "";
    }
}

/**
 * Load existing authentication headers for editing
 * @param {string} containerId - ID of the container to populate
 * @param {Array} headers - Array of header objects with key and value properties
 */
function loadAuthHeaders(containerId, headers) {
    const container = document.getElementById(containerId);
    if (!container || !headers || !Array.isArray(headers)) {
        return;
    }

    // Clear existing headers
    container.innerHTML = "";

    // Add each header
    headers.forEach((header) => {
        if (header.key && header.value) {
            addAuthHeader(containerId);
            // Find the last added header row and populate it
            const headerRows = container.querySelectorAll(
                '[id^="auth-header-"]',
            );
            const lastRow = headerRows[headerRows.length - 1];
            if (lastRow) {
                const keyInput = lastRow.querySelector(".auth-header-key");
                const valueInput = lastRow.querySelector(".auth-header-value");
                if (keyInput && valueInput) {
                    keyInput.value = header.key;
                    valueInput.value = header.value;
                }
            }
        }
    });

    updateAuthHeadersJSON(containerId);
}

// Expose authentication header functions to global scope
window.addAuthHeader = addAuthHeader;
window.removeAuthHeader = removeAuthHeader;
window.updateAuthHeadersJSON = updateAuthHeadersJSON;
window.loadAuthHeaders = loadAuthHeaders;

/**
 * Fetch tools from MCP server after OAuth completion for Authorization Code flow
 * @param {string} gatewayId - ID of the gateway to fetch tools for
 * @param {string} gatewayName - Name of the gateway for display purposes
 */
async function fetchToolsForGateway(gatewayId, gatewayName) {
    const button = document.getElementById(`fetch-tools-${gatewayId}`);
    if (!button) {
        return;
    }

    // Disable button and show loading state
    button.disabled = true;
    button.textContent = "⏳ Fetching...";
    button.className =
        "inline-block bg-yellow-600 hover:bg-yellow-700 text-white px-3 py-1 rounded text-sm mr-2";

    try {
        const response = await fetch(
            `${window.ROOT_PATH}/oauth/fetch-tools/${gatewayId}`,
            {
                method: "POST",
            },
        );

        const result = await response.json();

        if (response.ok) {
            // Success
            button.textContent = "✅ Tools Fetched";
            button.className =
                "inline-block bg-green-600 hover:bg-green-700 text-white px-3 py-1 rounded text-sm mr-2";

            // Show success message
            showSuccessMessage(
                `Successfully fetched ${result.tools_created} tools from ${gatewayName}`,
            );

            // Refresh the page to show the new tools
            setTimeout(() => {
                window.location.reload();
            }, 2000);
        } else {
            throw new Error(result.detail || "Failed to fetch tools");
        }
    } catch (error) {
        console.error("Failed to fetch tools:", error);

        // Show error state
        button.textContent = "❌ Retry";
        button.className =
            "inline-block bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm mr-2";
        button.disabled = false;

        // Show error message
        showErrorMessage(
            `Failed to fetch tools from ${gatewayName}: ${error.message}`,
        );
    }
}

// Expose fetch tools function to global scope
window.fetchToolsForGateway = fetchToolsForGateway;

console.log("🛡️ ContextForge MCP Gateway admin.js initialized");

// ===================================================================
// BULK IMPORT TOOLS — MODAL WIRING
// ===================================================================

function setupBulkImportModal() {
    const openBtn = safeGetElement("open-bulk-import", true);
    const modalId = "bulk-import-modal";
    const modal = safeGetElement(modalId, true);

    if (!openBtn || !modal) {
        // Bulk import feature not available - skip silently
        return;
    }

    // avoid double-binding if admin.js gets evaluated more than once
    if (openBtn.dataset.wired === "1") {
        return;
    }
    openBtn.dataset.wired = "1";

    const closeBtn = safeGetElement("close-bulk-import", true);
    const backdrop = safeGetElement("bulk-import-backdrop", true);
    const resultEl = safeGetElement("import-result", true);

    const focusTarget =
        modal?.querySelector("#tools_json") ||
        modal?.querySelector("#tools_file") ||
        modal?.querySelector("[data-autofocus]");

    // helpers
    const open = (e) => {
        if (e) {
            e.preventDefault();
        }
        // clear previous results each time we open
        if (resultEl) {
            resultEl.innerHTML = "";
        }
        openModal(modalId);
        // prevent background scroll
        document.documentElement.classList.add("overflow-hidden");
        document.body.classList.add("overflow-hidden");
        if (focusTarget) {
            setTimeout(() => focusTarget.focus(), 0);
        }
        return false;
    };

    const close = () => {
        // also clear results on close to keep things tidy
        closeModal(modalId, "import-result");
        document.documentElement.classList.remove("overflow-hidden");
        document.body.classList.remove("overflow-hidden");
    };

    // wire events
    openBtn.addEventListener("click", open);

    if (closeBtn) {
        closeBtn.addEventListener("click", (e) => {
            e.preventDefault();
            close();
        });
    }

    // click on backdrop only (not the dialog content) closes the modal
    if (backdrop) {
        backdrop.addEventListener("click", (e) => {
            if (e.target === backdrop) {
                close();
            }
        });
    }

    // ESC to close
    modal.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            e.stopPropagation();
            close();
        }
    });

    // FORM SUBMISSION → handle bulk import
    const form = safeGetElement("bulk-import-form", true);
    if (form) {
        form.addEventListener("submit", async (e) => {
            e.preventDefault();
            e.stopPropagation();
            const resultEl = safeGetElement("import-result", true);
            const indicator = safeGetElement("bulk-import-indicator", true);

            try {
                const formData = new FormData();

                // Get JSON from textarea or file
                const jsonTextarea = form?.querySelector('[name="tools_json"]');
                const fileInput = form?.querySelector('[name="tools_file"]');

                let hasData = false;

                // Check for file upload first (takes precedence)
                if (fileInput && fileInput.files.length > 0) {
                    formData.append("tools_file", fileInput.files[0]);
                    hasData = true;
                } else if (jsonTextarea && jsonTextarea.value.trim()) {
                    // Validate JSON before sending
                    try {
                        const toolsData = JSON.parse(jsonTextarea.value);
                        if (!Array.isArray(toolsData)) {
                            throw new Error("JSON must be an array of tools");
                        }
                        formData.append("tools", jsonTextarea.value);
                        hasData = true;
                    } catch (err) {
                        if (resultEl) {
                            resultEl.innerHTML = `
                                <div class="mt-2 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
                                    <p class="font-semibold">Invalid JSON</p>
                                    <p class="text-sm mt-1">${escapeHtml(err.message)}</p>
                                </div>
                            `;
                        }
                        return;
                    }
                }

                if (!hasData) {
                    if (resultEl) {
                        resultEl.innerHTML = `
                            <div class="mt-2 p-3 bg-yellow-100 border border-yellow-400 text-yellow-700 rounded">
                                <p class="text-sm">Please provide JSON data or upload a file</p>
                            </div>
                        `;
                    }
                    return;
                }

                // Show loading state
                if (indicator) {
                    indicator.style.display = "flex";
                }

                // Submit to backend
                const response = await fetchWithTimeout(
                    `${window.ROOT_PATH}/admin/tools/import`,
                    {
                        method: "POST",
                        body: formData,
                    },
                );

                const result = await response.json();

                // Display results
                if (resultEl) {
                    if (result.success) {
                        resultEl.innerHTML = `
                            <div class="mt-2 p-3 bg-green-100 border border-green-400 text-green-700 rounded">
                                <p class="font-semibold">Import Successful</p>
                                <p class="text-sm mt-1">${escapeHtml(result.message)}</p>
                            </div>
                        `;

                        // Close modal and refresh page after delay
                        setTimeout(() => {
                            closeModal("bulk-import-modal");
                            window.location.reload();
                        }, 2000);
                    } else if (result.imported > 0) {
                        // Partial success
                        let detailsHtml = "";
                        if (result.details && result.details.failed) {
                            detailsHtml =
                                '<ul class="mt-2 text-sm list-disc list-inside">';
                            result.details.failed.forEach((item) => {
                                detailsHtml += `<li><strong>${escapeHtml(item.name)}:</strong> ${escapeHtml(item.error)}</li>`;
                            });
                            detailsHtml += "</ul>";
                        }

                        resultEl.innerHTML = `
                            <div class="mt-2 p-3 bg-yellow-100 border border-yellow-400 text-yellow-700 rounded">
                                <p class="font-semibold">Partial Import</p>
                                <p class="text-sm mt-1">${escapeHtml(result.message)}</p>
                                ${detailsHtml}
                            </div>
                        `;
                    } else {
                        // Complete failure
                        resultEl.innerHTML = `
                            <div class="mt-2 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
                                <p class="font-semibold">Import Failed</p>
                                <p class="text-sm mt-1">${escapeHtml(result.message)}</p>
                            </div>
                        `;
                    }
                }
            } catch (error) {
                console.error("Bulk import error:", error);
                if (resultEl) {
                    resultEl.innerHTML = `
                        <div class="mt-2 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
                            <p class="font-semibold">Import Error</p>
                            <p class="text-sm mt-1">${escapeHtml(error.message || "An unexpected error occurred")}</p>
                        </div>
                    `;
                }
            } finally {
                // Hide loading state
                if (indicator) {
                    indicator.style.display = "none";
                }
            }

            return false;
        });
    }
}

// ===================================================================
// EXPORT/IMPORT FUNCTIONALITY
// ===================================================================

/**
 * Initialize export/import functionality
 */
function initializeExportImport() {
    // Prevent double initialization
    if (window.exportImportInitialized) {
        console.log("🔄 Export/import already initialized, skipping");
        return;
    }

    console.log("🔄 Initializing export/import functionality");

    // Export button handlers
    const exportAllBtn = document.getElementById("export-all-btn");
    const exportSelectedBtn = document.getElementById("export-selected-btn");

    if (exportAllBtn) {
        exportAllBtn.addEventListener("click", handleExportAll);
    }

    if (exportSelectedBtn) {
        exportSelectedBtn.addEventListener("click", handleExportSelected);
    }

    // Import functionality
    const importDropZone = document.getElementById("import-drop-zone");
    const importFileInput = document.getElementById("import-file-input");
    const importValidateBtn = document.getElementById("import-validate-btn");
    const importExecuteBtn = document.getElementById("import-execute-btn");

    if (importDropZone && importFileInput) {
        // File input handler
        importDropZone.addEventListener("click", () => importFileInput.click());
        importFileInput.addEventListener("change", handleFileSelect);

        // Drag and drop handlers
        importDropZone.addEventListener("dragover", handleDragOver);
        importDropZone.addEventListener("drop", handleFileDrop);
        importDropZone.addEventListener("dragleave", handleDragLeave);
    }

    if (importValidateBtn) {
        importValidateBtn.addEventListener("click", () => handleImport(true));
    }

    if (importExecuteBtn) {
        importExecuteBtn.addEventListener("click", () => handleImport(false));
    }

    // Load recent imports when tab is shown
    loadRecentImports();

    // Mark as initialized
    window.exportImportInitialized = true;
}

/**
 * Handle export all configuration
 */
async function handleExportAll() {
    console.log("📤 Starting export all configuration");

    try {
        showExportProgress(true);

        const options = getExportOptions();
        const params = new URLSearchParams();

        if (options.types.length > 0) {
            params.append("types", options.types.join(","));
        }
        if (options.tags) {
            params.append("tags", options.tags);
        }
        if (options.includeInactive) {
            params.append("include_inactive", "true");
        }
        if (!options.includeDependencies) {
            params.append("include_dependencies", "false");
        }

        const response = await fetch(
            `${window.ROOT_PATH}/admin/export/configuration?${params}`,
            {
                method: "GET",
                headers: {
                    Authorization: `Bearer ${await getAuthToken()}`,
                },
            },
        );

        if (!response.ok) {
            throw new Error(`Export failed: ${response.statusText}`);
        }

        // Create download
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `mcpgateway-export-${new Date().toISOString().slice(0, 19).replace(/:/g, "-")}.json`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        showNotification("✅ Export completed successfully!", "success");
    } catch (error) {
        console.error("Export error:", error);
        showNotification(`❌ Export failed: ${error.message}`, "error");
    } finally {
        showExportProgress(false);
    }
}

/**
 * Handle export selected configuration
 */
async function handleExportSelected() {
    console.log("📋 Starting selective export");

    try {
        showExportProgress(true);

        // This would need entity selection logic - for now, just do a filtered export
        await handleExportAll(); // Simplified implementation
    } catch (error) {
        console.error("Selective export error:", error);
        showNotification(
            `❌ Selective export failed: ${error.message}`,
            "error",
        );
    } finally {
        showExportProgress(false);
    }
}

/**
 * Get export options from form
 */
function getExportOptions() {
    const types = [];

    if (document.getElementById("export-tools")?.checked) {
        types.push("tools");
    }
    if (document.getElementById("export-gateways")?.checked) {
        types.push("gateways");
    }
    if (document.getElementById("export-servers")?.checked) {
        types.push("servers");
    }
    if (document.getElementById("export-prompts")?.checked) {
        types.push("prompts");
    }
    if (document.getElementById("export-resources")?.checked) {
        types.push("resources");
    }
    if (document.getElementById("export-roots")?.checked) {
        types.push("roots");
    }

    return {
        types,
        tags: document.getElementById("export-tags")?.value || "",
        includeInactive:
            document.getElementById("export-include-inactive")?.checked ||
            false,
        includeDependencies:
            document.getElementById("export-include-dependencies")?.checked ||
            true,
    };
}

/**
 * Show/hide export progress
 */
function showExportProgress(show) {
    const progressEl = document.getElementById("export-progress");
    if (progressEl) {
        progressEl.classList.toggle("hidden", !show);
        if (show) {
            let progress = 0;
            const progressBar = document.getElementById("export-progress-bar");
            const interval = setInterval(() => {
                progress += 10;
                if (progressBar) {
                    progressBar.style.width = `${Math.min(progress, 90)}%`;
                }
                if (progress >= 100) {
                    clearInterval(interval);
                }
            }, 200);
        }
    }
}

/**
 * Handle file selection for import
 */
function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        processImportFile(file);
    }
}

/**
 * Handle drag over for file drop
 */
function handleDragOver(event) {
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
    event.currentTarget.classList.add(
        "border-blue-500",
        "bg-blue-50",
        "dark:bg-blue-900",
    );
}

/**
 * Handle drag leave
 */
function handleDragLeave(event) {
    event.preventDefault();
    event.currentTarget.classList.remove(
        "border-blue-500",
        "bg-blue-50",
        "dark:bg-blue-900",
    );
}

/**
 * Handle file drop
 */
function handleFileDrop(event) {
    event.preventDefault();
    event.currentTarget.classList.remove(
        "border-blue-500",
        "bg-blue-50",
        "dark:bg-blue-900",
    );

    const files = event.dataTransfer.files;
    if (files.length > 0) {
        processImportFile(files[0]);
    }
}

/**
 * Process selected import file
 */
function processImportFile(file) {
    console.log("📁 Processing import file:", file.name);

    if (!file.type.includes("json")) {
        showNotification("❌ Please select a JSON file", "error");
        return;
    }

    const reader = new FileReader();
    reader.onload = function (e) {
        try {
            const importData = JSON.parse(e.target.result);

            // Validate basic structure
            if (!importData.version || !importData.entities) {
                throw new Error("Invalid import file format");
            }

            // Store import data and enable buttons
            window.currentImportData = importData;

            const previewBtn = document.getElementById("import-preview-btn");
            const validateBtn = document.getElementById("import-validate-btn");
            const executeBtn = document.getElementById("import-execute-btn");

            if (previewBtn) {
                previewBtn.disabled = false;
            }
            if (validateBtn) {
                validateBtn.disabled = false;
            }
            if (executeBtn) {
                executeBtn.disabled = false;
            }

            // Update drop zone to show file loaded
            updateDropZoneStatus(file.name, importData);

            showNotification(`✅ Import file loaded: ${file.name}`, "success");
        } catch (error) {
            console.error("File processing error:", error);
            showNotification(`❌ Invalid JSON file: ${error.message}`, "error");
        }
    };

    reader.readAsText(file);
}

/**
 * Update drop zone to show loaded file
 */
function updateDropZoneStatus(fileName, importData) {
    const dropZone = document.getElementById("import-drop-zone");
    if (dropZone) {
        const entityCounts = importData.metadata?.entity_counts || {};
        const totalEntities = Object.values(entityCounts).reduce(
            (sum, count) => sum + count,
            0,
        );

        dropZone.innerHTML = `
            <div class="space-y-2">
                <svg class="mx-auto h-8 w-8 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <div class="text-sm text-gray-900 dark:text-white font-medium">
                    📁 ${escapeHtml(fileName)}
                </div>
                <div class="text-xs text-gray-500 dark:text-gray-400">
                    ${totalEntities} entities • Version ${escapeHtml(importData.version || "unknown")}
                </div>
                <button class="text-xs text-blue-600 dark:text-blue-400 hover:underline" onclick="resetImportFile()">
                    Choose different file
                </button>
            </div>
        `;
    }
}

/**
 * Reset import file selection
 */
function resetImportFile() {
    window.currentImportData = null;

    const dropZone = document.getElementById("import-drop-zone");
    if (dropZone) {
        dropZone.innerHTML = `
            <div class="space-y-2">
                <svg class="mx-auto h-12 w-12 text-gray-400" stroke="currentColor" fill="none" viewBox="0 0 48 48">
                    <path d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3-3m-3 3l3 3m-3-3V8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                <div class="text-sm text-gray-600 dark:text-gray-300">
                    <span class="font-medium text-blue-600 dark:text-blue-400">Click to upload</span>
                    or drag and drop
                </div>
                <p class="text-xs text-gray-500 dark:text-gray-400">JSON export files only</p>
            </div>
        `;
    }

    const previewBtn = document.getElementById("import-preview-btn");
    const validateBtn = document.getElementById("import-validate-btn");
    const executeBtn = document.getElementById("import-execute-btn");

    if (previewBtn) {
        previewBtn.disabled = true;
    }
    if (validateBtn) {
        validateBtn.disabled = true;
    }
    if (executeBtn) {
        executeBtn.disabled = true;
    }

    // Hide status section
    const statusSection = document.getElementById("import-status-section");
    if (statusSection) {
        statusSection.classList.add("hidden");
    }
}

/**
 * Preview import file for selective import
 */
async function previewImport() {
    console.log("🔍 Generating import preview...");

    if (!window.currentImportData) {
        showNotification("❌ Please select an import file first", "error");
        return;
    }

    try {
        showImportProgress(true);

        const response = await fetch(
            (window.ROOT_PATH || "") + "/admin/import/preview",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${await getAuthToken()}`,
                },
                body: JSON.stringify({ data: window.currentImportData }),
            },
        );

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(
                errorData.detail || `Preview failed: ${response.statusText}`,
            );
        }

        const result = await response.json();
        displayImportPreview(result.preview);

        showNotification("✅ Import preview generated successfully", "success");
    } catch (error) {
        console.error("Import preview error:", error);
        showNotification(`❌ Preview failed: ${error.message}`, "error");
    } finally {
        showImportProgress(false);
    }
}

/**
 * Handle import (validate or execute)
 */
async function handleImport(dryRun = false) {
    console.log(`🔄 Starting import (dry_run=${dryRun})`);

    if (!window.currentImportData) {
        showNotification("❌ Please select an import file first", "error");
        return;
    }

    try {
        showImportProgress(true);

        const conflictStrategy =
            document.getElementById("import-conflict-strategy")?.value ||
            "update";
        const rekeySecret =
            document.getElementById("import-rekey-secret")?.value || null;

        const requestData = {
            import_data: window.currentImportData,
            conflict_strategy: conflictStrategy,
            dry_run: dryRun,
            rekey_secret: rekeySecret,
        };

        const response = await fetch(
            (window.ROOT_PATH || "") + "/admin/import/configuration",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${await getAuthToken()}`,
                },
                body: JSON.stringify(requestData),
            },
        );

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(
                errorData.detail || `Import failed: ${response.statusText}`,
            );
        }

        const result = await response.json();
        displayImportResults(result, dryRun);

        if (!dryRun) {
            // Refresh the current tab data if import was successful
            refreshCurrentTabData();
        }
    } catch (error) {
        console.error("Import error:", error);
        showNotification(`❌ Import failed: ${error.message}`, "error");
    } finally {
        showImportProgress(false);
    }
}

/**
 * Display import results
 */
function displayImportResults(result, isDryRun) {
    const statusSection = document.getElementById("import-status-section");
    if (statusSection) {
        statusSection.classList.remove("hidden");
    }

    const progress = result.progress || {};

    // Update progress bars and counts
    updateImportCounts(progress);

    // Show messages
    displayImportMessages(result.errors || [], result.warnings || [], isDryRun);

    const action = isDryRun ? "validation" : "import";
    const statusText = result.status || "completed";
    showNotification(`✅ ${action} ${statusText}!`, "success");
}

/**
 * Update import progress counts
 */
function updateImportCounts(progress) {
    const total = progress.total || 0;
    const processed = progress.processed || 0;
    const created = progress.created || 0;
    const updated = progress.updated || 0;
    const failed = progress.failed || 0;

    document.getElementById("import-total").textContent = total;
    document.getElementById("import-created").textContent = created;
    document.getElementById("import-updated").textContent = updated;
    document.getElementById("import-failed").textContent = failed;

    // Update progress bar
    const progressBar = document.getElementById("import-progress-bar");
    const progressText = document.getElementById("import-progress-text");

    if (progressBar && progressText && total > 0) {
        const percentage = Math.round((processed / total) * 100);
        progressBar.style.width = `${percentage}%`;
        progressText.textContent = `${percentage}%`;
    }
}

/**
 * Display import messages (errors and warnings)
 */
function displayImportMessages(errors, warnings, isDryRun) {
    const messagesContainer = document.getElementById("import-messages");
    if (!messagesContainer) {
        return;
    }

    messagesContainer.innerHTML = "";

    // Show errors
    if (errors.length > 0) {
        const errorDiv = document.createElement("div");
        errorDiv.className =
            "bg-red-100 dark:bg-red-900 border border-red-400 dark:border-red-600 text-red-700 dark:text-red-300 px-4 py-3 rounded";
        errorDiv.innerHTML = `
            <div class="font-bold">❌ Errors (${errors.length})</div>
            <ul class="mt-2 text-sm list-disc list-inside">
                ${errors
                    .slice(0, 5)
                    .map((error) => `<li>${escapeHtml(error)}</li>`)
                    .join("")}
                ${errors.length > 5 ? `<li class="text-gray-600 dark:text-gray-400">... and ${errors.length - 5} more errors</li>` : ""}
            </ul>
        `;
        messagesContainer.appendChild(errorDiv);
    }

    // Show warnings
    if (warnings.length > 0) {
        const warningDiv = document.createElement("div");
        warningDiv.className =
            "bg-yellow-100 dark:bg-yellow-900 border border-yellow-400 dark:border-yellow-600 text-yellow-700 dark:text-yellow-300 px-4 py-3 rounded";
        const warningTitle = isDryRun ? "🔍 Would Import" : "⚠️ Warnings";
        warningDiv.innerHTML = `
            <div class="font-bold">${warningTitle} (${warnings.length})</div>
            <ul class="mt-2 text-sm list-disc list-inside">
                ${warnings
                    .slice(0, 5)
                    .map((warning) => `<li>${escapeHtml(warning)}</li>`)
                    .join("")}
                ${warnings.length > 5 ? `<li class="text-gray-600 dark:text-gray-400">... and ${warnings.length - 5} more warnings</li>` : ""}
            </ul>
        `;
        messagesContainer.appendChild(warningDiv);
    }
}

/**
 * Show/hide import progress
 */
function showImportProgress(show) {
    // Disable/enable buttons during operation
    const previewBtn = document.getElementById("import-preview-btn");
    const validateBtn = document.getElementById("import-validate-btn");
    const executeBtn = document.getElementById("import-execute-btn");

    if (previewBtn) {
        previewBtn.disabled = show;
    }
    if (validateBtn) {
        validateBtn.disabled = show;
    }
    if (executeBtn) {
        executeBtn.disabled = show;
    }
}

/**
 * Load recent import operations
 */
async function loadRecentImports() {
    try {
        const response = await fetch(
            (window.ROOT_PATH || "") + "/admin/import/status",
            {
                headers: {
                    Authorization: `Bearer ${await getAuthToken()}`,
                },
            },
        );

        if (response.ok) {
            const imports = await response.json();
            console.log("Loaded recent imports:", imports.length);
        }
    } catch (error) {
        console.error("Failed to load recent imports:", error);
    }
}

/**
 * Refresh current tab data after successful import
 */
function refreshCurrentTabData() {
    // Find the currently active tab and refresh its data
    const activeTab = document.querySelector(".tab-link.figma-blue-border");
    if (activeTab) {
        const href = activeTab.getAttribute("href");
        if (href === "#catalog") {
            // Refresh servers
            if (typeof window.loadCatalog === "function") {
                window.loadCatalog();
            }
        } else if (href === "#tools") {
            // Refresh tools
            if (typeof window.loadTools === "function") {
                window.loadTools();
            }
        } else if (href === "#gateways") {
            // Refresh gateways
            if (typeof window.loadGateways === "function") {
                window.loadGateways();
            }
        }
        // Add other tab refresh logic as needed
    }
}

/**
 * Show notification (simple implementation)
 */
function showNotification(message, type = "info") {
    console.log(`${type.toUpperCase()}: ${message}`);

    // Create a simple toast notification
    const toast = document.createElement("div");
    toast.className = `fixed top-4 right-4 z-50 px-4 py-3 rounded-md text-sm font-medium max-w-sm ${
        type === "success"
            ? "bg-green-100 text-green-800 border border-green-400"
            : type === "error"
              ? "bg-red-100 text-red-800 border border-red-400"
              : "bg-blue-100 text-blue-800 border border-blue-400"
    }`;
    toast.textContent = message;

    document.body.appendChild(toast);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (toast.parentNode) {
            toast.parentNode.removeChild(toast);
        }
    }, 5000);
}

/**
 * Utility function to get cookie value
 */
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) {
        return parts.pop().split(";").shift();
    }
    return "";
}

// Expose functions used in dynamically generated HTML
window.resetImportFile = resetImportFile;

// ===================================================================
// A2A AGENT TESTING FUNCTIONALITY
// ===================================================================

/**
 * Test an A2A agent by making a direct invocation call
 * @param {string} agentId - ID of the agent to test
 * @param {string} agentName - Name of the agent for display
 * @param {string} endpointUrl - Endpoint URL of the agent
 */
async function testA2AAgent(agentId, agentName, endpointUrl) {
    try {
        // Show loading state
        const testResult = document.getElementById(`test-result-${agentId}`);
        testResult.innerHTML =
            '<div class="text-blue-600">🔄 Testing agent...</div>';
        testResult.classList.remove("hidden");

        // Get auth token using the robust getAuthToken function
        const token = await getAuthToken();

        // Debug logging
        console.log("Available cookies:", document.cookie);
        console.log(
            "Found token:",
            token ? "Yes (length: " + token.length + ")" : "No",
        );

        // Prepare headers
        const headers = {
            "Content-Type": "application/json",
        };

        if (token) {
            headers.Authorization = `Bearer ${token}`;
        } else {
            // Fallback to basic auth if JWT not available
            console.warn("JWT token not found, attempting basic auth fallback");
            headers.Authorization = "Basic " + btoa("admin:changeme"); // Default admin credentials
        }

        // Test payload is now determined server-side based on agent configuration
        const testPayload = {};

        // Make test request to A2A agent via admin endpoint
        const response = await fetchWithTimeout(
            `${window.ROOT_PATH}/admin/a2a/${agentId}/test`,
            {
                method: "POST",
                headers,
                body: JSON.stringify(testPayload),
            },
            window.MCPGATEWAY_UI_TOOL_TEST_TIMEOUT || 60000, // Use configurable timeout
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const result = await response.json();

        // Display result
        let resultHtml;
        if (!result.success || result.error) {
            resultHtml = `
                <div class="text-red-600">
                    <div>❌ Test Failed</div>
                    <div class="text-xs mt-1">Error: ${escapeHtml(result.error || "Unknown error")}</div>
                </div>`;
        } else {
            // Check if the agent result contains an error (agent-level error)
            const agentResult = result.result;
            if (agentResult && agentResult.error) {
                resultHtml = `
                    <div class="text-yellow-600">
                        <div>⚠️ Agent Error</div>
                        <div class="text-xs mt-1">Agent Response: ${escapeHtml(JSON.stringify(agentResult).substring(0, 150))}...</div>
                    </div>`;
            } else {
                resultHtml = `
                    <div class="text-green-600">
                        <div>✅ Test Successful</div>
                        <div class="text-xs mt-1">Response: ${escapeHtml(JSON.stringify(agentResult).substring(0, 150))}...</div>
                    </div>`;
            }
        }

        testResult.innerHTML = resultHtml;

        // Auto-hide after 10 seconds
        setTimeout(() => {
            testResult.classList.add("hidden");
        }, 10000);
    } catch (error) {
        console.error("A2A agent test failed:", error);

        const testResult = document.getElementById(`test-result-${agentId}`);
        testResult.innerHTML = `
            <div class="text-red-600">
                <div>❌ Test Failed</div>
                <div class="text-xs mt-1">Error: ${escapeHtml(error.message)}</div>
            </div>`;
        testResult.classList.remove("hidden");

        // Auto-hide after 10 seconds
        setTimeout(() => {
            testResult.classList.add("hidden");
        }, 10000);
    }
}

// Expose A2A test function to global scope
window.testA2AAgent = testA2AAgent;

/**
 * Token Management Functions
 *
 * Updated to support:
 * - Personal tokens (user): /tokens
 * - Team tokens (user): /tokens/teams/{team_id}
 * - Admin tokens (permission-driven): /tokens/admin/*
 * - Graceful no-permission UX: if elements don't exist, do nothing
 *
 * NOTE:
 * - Keeps your existing patterns (fetchWithTimeout, safeGetElement, showNotification).
 * - Minimal changes only: add endpoint resolver + use it in existing calls.
 */

/**
 * ============================================================
 * Endpoint Resolver (NEW - minimal)
 * Uses permission-derived flag injected by admin.html:
 *   window.__TOKENS_IS_ADMIN__ = true/false
 * ============================================================
 */

async function copyToClipboard(elementId) {
  const el = document.getElementById(elementId);

  if (!el) {
    console.error(`copyToClipboard: Element not found -> ${elementId}`);
    showErrorMessage("Unable to copy. Element not found.");
    return;
  }

  // Support input, textarea, or normal elements
  const textToCopy =
    el.value !== undefined ? el.value : el.textContent || "";

  if (!textToCopy) {
    showErrorMessage("Nothing to copy.");
    return;
  }

  try {
    // Modern Clipboard API (works on HTTPS or localhost)
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      await navigator.clipboard.writeText(textToCopy);
      showSuccessMessage("Copied to clipboard!");
      return;
    }

    // Fallback for HTTP / older browsers
    const temp = document.createElement("textarea");
    temp.value = textToCopy;
    temp.setAttribute("readonly", "");
    temp.style.position = "fixed";
    temp.style.left = "-9999px";
    document.body.appendChild(temp);

    temp.select();
    document.execCommand("copy");
    document.body.removeChild(temp);

    showSuccessMessage("Copied to clipboard!");
  } catch (error) {
    console.error("Clipboard copy failed:", error);

    // Final fallback: select text manually
    if (el.select) {
      el.focus();
      el.select();
      el.setSelectionRange?.(0, 99999);
    }

    showErrorMessage("Clipboard blocked. Please press Ctrl+C.");
  }
}

function tokensIsAdmin() {
  return !!window.__TOKENS_IS_ADMIN__;
}

function tokensBase() {
  return `${window.ROOT_PATH}/tokens`;
}

function tokensEndpoints() {
  const base = tokensBase();

  return {
    // Personal
    personalList: () => (tokensIsAdmin() ? `${base}/admin/personal` : `${base}`),
    personalCreate: () => `${base}`, // still same for admin/user (creates for current_user)
    personalRevoke: (tokenId) =>
      (tokensIsAdmin()
        ? `${base}/admin/${encodeURIComponent(tokenId)}`
        : `${base}/${encodeURIComponent(tokenId)}`),
    personalUsage: (tokenId) =>
      (tokensIsAdmin()
        ? `${base}/admin/${encodeURIComponent(tokenId)}/usage`
        : `${base}/${encodeURIComponent(tokenId)}/usage`),

    // Team
    teamList: (teamId) =>
      (tokensIsAdmin()
        ? `${base}/admin/teams/${encodeURIComponent(teamId)}`
        : `${base}/teams/${encodeURIComponent(teamId)}`),
    teamCreate: (teamId) =>
      (tokensIsAdmin()
        ? `${base}/admin/teams/${encodeURIComponent(teamId)}`
        : `${base}/teams/${encodeURIComponent(teamId)}`),
  };
}

/**
 * Load personal tokens list from API
 */
async function loadTokensList() {
  const tokensList = safeGetElement("tokens-list");
  if (!tokensList) return; // user may not have read permission -> UI not rendered

  try {
    tokensList.innerHTML =
      '<p class="text-gray-500 dark:text-gray-400">Loading tokens...</p>';

    const response = await fetchWithTimeout(tokensEndpoints().personalList(), {
      headers: {
        Authorization: `Bearer ${await getAuthToken()}`,
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to load tokens: ${response.status}`);
    }

    const data = await response.json();
    displayTokensList(data.tokens);
  } catch (error) {
    console.error("Error loading tokens:", error);
    tokensList.innerHTML = `<div class="text-red-500">Error loading tokens: ${escapeHtml(error.message)}</div>`;
  }
}

/**
 * Load team tokens list from API (single definition - FIX)
 */
async function loadTeamTokensList(teamId) {
  const teamTokensList = safeGetElement("team-tokens-list");
  if (!teamTokensList) return; // user may not have team read permission -> UI not rendered

  if (!teamId) {
    teamTokensList.innerHTML =
      '<p class="text-gray-500 dark:text-gray-400">Select a team to load tokens.</p>';
    return;
  }

  try {
    teamTokensList.innerHTML =
      '<p class="text-gray-500 dark:text-gray-400">Loading team tokens...</p>';

    const url =
      `${tokensEndpoints().teamList(teamId)}?include_inactive=false&limit=50&offset=0`;

    const response = await fetchWithTimeout(url, {
      headers: {
        Authorization: `Bearer ${await getAuthToken()}`,
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      const err = await safeJson(response);
      const msg = (err && err.detail)
        ? err.detail
        : `Failed to load team tokens: ${response.status}`;
      throw new Error(msg);
    }

    const data = await response.json();
    displayTeamTokensList(data.tokens || []);
  } catch (error) {
    console.error("Error loading team tokens:", error);
    teamTokensList.innerHTML = `<div class="text-red-500">Error loading team tokens: ${escapeHtml(error.message)}</div>`;
  }
}

/**
 * Show modal with new token (one-time display)
 */
function showTokenCreatedModal(tokenData) {
  const modal = document.createElement("div");
  modal.className =
    "fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50";

  modal.innerHTML = `
  <div class="relative top-20 mx-auto p-5 border w-11/12 max-w-lg shadow-lg rounded-md bg-white dark:bg-gray-800">
   <div class="mt-3">
    <div class="flex items-center justify-between mb-4">
     <h3 class="text-lg font-medium text-gray-900 dark:text-white">Token Created Successfully</h3>
     <button onclick="this.closest('.fixed').remove()" class="text-gray-400 hover:text-gray-600">
      <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
       <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
      </svg>
     </button>
    </div>

    <div class="bg-yellow-50 dark:bg-yellow-900 border border-yellow-200 dark:border-yellow-700 rounded-md p-4 mb-4">
     <div class="flex">
      <div class="flex-shrink-0">
       <svg class="h-5 w-5 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
        <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
       </svg>
      </div>
      <div class="ml-3">
       <h3 class="text-sm font-medium text-yellow-800 dark:text-yellow-200">
        Important: Save your token now!
       </h3>
       <div class="mt-2 text-sm text-yellow-700 dark:text-yellow-300">
        This is the only time you will be able to see this token. Save it securely.
       </div>
      </div>
     </div>
    </div>

    <div class="mb-4">
     <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
      Your API Token:
     </label>
     <div class="flex">
      <input
       type="text"
       value="${tokenData.access_token}"
       readonly
       class="flex-1 p-2 border border-gray-300 dark:border-gray-600 rounded-l-md bg-gray-50 dark:bg-gray-700 text-sm font-mono"
       id="new-token-value"
      />
      <button
       onclick="copyToClipboard('new-token-value')"
       class="px-3 py-2 bg-indigo-600 text-white text-sm rounded-r-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
      >
       Copy
      </button>
     </div>
    </div>

    <div class="text-sm text-gray-600 dark:text-gray-400 mb-4">
     <strong>Token Name:</strong> ${escapeHtml(tokenData.token?.name || "Unnamed Token")}<br/>
     <strong>Expires:</strong> ${
      tokenData.token?.expires_at
       ? new Date(tokenData.token.expires_at).toLocaleDateString()
       : "Never"
     }
    </div>

    <div class="flex justify-end">
     <button
      onclick="this.closest('.fixed').remove()"
      class="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
     >
      I've Saved It
     </button>
    </div>
   </div>
  </div>
 `;

  document.body.appendChild(modal);

  const tokenInput = modal.querySelector("#new-token-value");
  if (tokenInput) {
    tokenInput.focus();
    tokenInput.select();
  }
}

/**
 * Show usage statistics modal
 */
function showUsageStatsModal(stats) {
  const modal = document.createElement("div");
  modal.className =
    "fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50";

  modal.innerHTML = `
  <div class="relative top-20 mx-auto p-5 border w-11/12 max-w-2xl shadow-lg rounded-md bg-white dark:bg-gray-800">
   <div class="flex items-center justify-between mb-4">
    <h3 class="text-lg font-medium text-gray-900 dark:text-white">
     Token Usage Statistics (Last ${stats.period_days} Days)
    </h3>
    <button onclick="this.closest('.fixed').remove()" class="text-gray-400 hover:text-gray-600">
     <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
     </svg>
    </button>
   </div>

   <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
    <div class="bg-blue-50 dark:bg-blue-900 p-4 rounded-lg">
     <div class="text-2xl font-bold text-blue-600 dark:text-blue-300">${stats.total_requests}</div>
     <div class="text-sm text-blue-600 dark:text-blue-400">Total Requests</div>
    </div>
    <div class="bg-green-50 dark:bg-green-900 p-4 rounded-lg">
     <div class="text-2xl font-bold text-green-600 dark:text-green-300">${stats.successful_requests}</div>
     <div class="text-sm text-green-600 dark:text-green-400">Successful</div>
    </div>
    <div class="bg-red-50 dark:bg-red-900 p-4 rounded-lg">
     <div class="text-2xl font-bold text-red-600 dark:text-red-300">${stats.blocked_requests}</div>
     <div class="text-sm text-red-600 dark:text-red-400">Blocked</div>
    </div>
    <div class="bg-purple-50 dark:bg-purple-900 p-4 rounded-lg">
     <div class="text-2xl font-bold text-purple-600 dark:text-purple-300">${Math.round((stats.success_rate || 0) * 100)}%</div>
     <div class="text-sm text-purple-600 dark:text-purple-400">Success Rate</div>
    </div>
   </div>

   <div class="mb-4">
    <h4 class="text-md font-medium text-gray-900 dark:text-white mb-2">Average Response Time</h4>
    <div class="text-lg text-gray-700 dark:text-gray-300">${stats.average_response_time_ms}ms</div>
   </div>

   ${
     stats.top_endpoints && stats.top_endpoints.length > 0
       ? `
    <div class="mb-4">
     <h4 class="text-md font-medium text-gray-900 dark:text-white mb-2">Top Endpoints</h4>
     <div class="space-y-2">
      ${stats.top_endpoints
        .map(
          ([endpoint, count]) => `
       <div class="flex justify-between items-center p-2 bg-gray-50 dark:bg-gray-700 rounded">
        <span class="font-mono text-sm">${escapeHtml(endpoint)}</span>
        <span class="text-sm font-medium">${count} requests</span>
       </div>
      `
        )
        .join("")}
     </div>
    </div>
   `
       : ""
   }

   <div class="flex justify-end">
    <button
     onclick="this.closest('.fixed').remove()"
     class="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-500"
    >
     Close
    </button>
   </div>
  </div>
 `;

  document.body.appendChild(modal);
}

async function loadTeamsForTokenDropdown() {
  const select = safeGetElement("team-token-team-select");
  if (!select) return;

  // Prevent duplicate reload
  const alreadyLoaded = Array.from(select.options).some(
    (o) => o.value && o.value !== ""
  );
  if (alreadyLoaded) return;

  select.innerHTML = `<option value="">Loading teams...</option>`;

  try {
    const response = await fetchWithTimeout(`${window.ROOT_PATH}/teams`, {
      headers: {
        Authorization: `Bearer ${await getAuthToken()}`,
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to load teams: ${response.status}`);
    }

    const data = await response.json();

    // Handle both { teams: [] } or [] shapes
    const teams = Array.isArray(data) ? data : (data.teams || []);

    // Prefer owner teams for team tokens
    const ownedTeams = teams.filter(
      (t) => (t.role || t.relationship || "").toLowerCase() === "owner"
    );

    const list = ownedTeams.length ? ownedTeams : teams;

    if (!list.length) {
      select.innerHTML = `<option value="">No teams available</option>`;
      return;
    }

    select.innerHTML =
      `<option value="">-- Select a team --</option>` +
      list
        .map(
          (t) =>
            `<option value="${escapeHtml(t.id)}">${escapeHtml(t.name)}</option>`
        )
        .join("");
  } catch (error) {
    console.error("Error loading teams for token dropdown:", error);
    select.innerHTML = `<option value="">Error loading teams</option>`;
  }
}

/**
 * Display personal tokens list in the UI
 */
function displayTokensList(tokens) {
  const tokensList = safeGetElement("tokens-list");
  if (!tokensList) return;

  if (!tokens || tokens.length === 0) {
    tokensList.innerHTML =
      '<p class="text-gray-500 dark:text-gray-400">No tokens found. Create your first token above.</p>';
    return;
  }

  let tokensHTML = "";
  tokens.forEach((token) => {
    const expiresText = token.expires_at
      ? new Date(token.expires_at).toLocaleDateString()
      : "Never";
    const lastUsedText = token.last_used
      ? new Date(token.last_used).toLocaleDateString()
      : "Never";

    const statusBadge = token.is_active
      ? '<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-800 dark:text-green-100">Active</span>'
      : '<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800 dark:bg-red-800 dark:text-red-100">Inactive</span>';

    const createdText = token.created_at
      ? new Date(token.created_at).toLocaleDateString()
      : "—";

    tokensHTML += `
      <div class="border border-gray-200 dark:border-gray-600 rounded-lg p-4 mb-4">
        <div class="flex justify-between items-start">
          <div class="flex-1">
            <div class="flex items-center space-x-2">
              <h4 class="text-lg font-medium text-gray-900 dark:text-white">${escapeHtml(token.name)}</h4>
              ${statusBadge}
            </div>
            ${token.description ? `<p class="text-sm text-gray-600 dark:text-gray-400 mt-1">${escapeHtml(token.description)}</p>` : ""}
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mt-3 text-sm text-gray-500 dark:text-gray-400">
              <div>
                <span class="font-medium">Created:</span> ${createdText}
              </div>
              <div>
                <span class="font-medium">Expires:</span> ${expiresText}
              </div>
              <div>
                <span class="font-medium">Last Used:</span> ${lastUsedText}
              </div>
            </div>
            ${token.server_id ? `<div class="mt-2 text-sm"><span class="font-medium text-gray-700 dark:text-gray-300">Scoped to Server:</span> ${escapeHtml(token.server_id)}</div>` : ""}
            ${token.resource_scopes && token.resource_scopes.length > 0 ? `<div class="mt-1 text-sm"><span class="font-medium text-gray-700 dark:text-gray-300">Permissions:</span> ${token.resource_scopes.map((p) => escapeHtml(p)).join(", ")}</div>` : ""}
          </div>
          <div class="flex space-x-2 ml-4">
            <button
              onclick="viewTokenUsage('${token.id}')"
              class="px-3 py-1 text-sm font-medium text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 border border-blue-300 dark:border-blue-600 hover:border-blue-500 dark:hover:border-blue-400 rounded-md"
            >
              Usage Stats
            </button>
            <button
              onclick="revokeToken('${token.id}', '${escapeHtml(token.name)}')"
              class="px-3 py-1 text-sm font-medium text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300 border border-red-300 dark:border-red-600 hover:border-red-500 dark:hover:border-blue-400 rounded-md"
            >
              Revoke
            </button>
          </div>
        </div>
      </div>
    `;
  });

  tokensList.innerHTML = tokensHTML;
}

function displayTeamTokensList(tokens) {
  const listEl = safeGetElement("team-tokens-list");
  if (!listEl) return;

  if (!tokens || tokens.length === 0) {
    listEl.innerHTML = `<p class="text-gray-500 dark:text-gray-400">No team tokens found for this team.</p>`;
    return;
  }

  let html = "";
  tokens.forEach((token) => {
    const expiresText = token.expires_at ? new Date(token.expires_at).toLocaleDateString() : "Never";
    const lastUsedText = token.last_used ? new Date(token.last_used).toLocaleDateString() : "Never";

    const statusBadge = token.is_active
      ? '<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-800 dark:text-green-100">Active</span>'
      : '<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800 dark:bg-red-800 dark:text-red-100">Inactive</span>';

    html += `
   <div class="border border-gray-200 dark:border-gray-600 rounded-lg p-4 mb-4">
    <div class="flex justify-between items-start">
     <div class="flex-1">
      <div class="flex items-center space-x-2">
       <h4 class="text-lg font-medium text-gray-900 dark:text-white">${escapeHtml(token.name)}</h4>
       ${statusBadge}
      </div>
      ${token.description ? `<p class="text-sm text-gray-600 dark:text-gray-400 mt-1">${escapeHtml(token.description)}</p>` : ""}

      <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mt-3 text-sm text-gray-500 dark:text-gray-400">
       <div><span class="font-medium">Created:</span> ${token.created_at ? new Date(token.created_at).toLocaleDateString() : "-"}</div>
       <div><span class="font-medium">Expires:</span> ${expiresText}</div>
       <div><span class="font-medium">Last Used:</span> ${lastUsedText}</div>
      </div>

      ${token.server_id ? `<div class="mt-2 text-sm"><span class="font-medium text-gray-700 dark:text-gray-300">Scoped to Server:</span> ${escapeHtml(token.server_id)}</div>` : ""}
      ${token.resource_scopes && token.resource_scopes.length > 0 ? `<div class="mt-1 text-sm"><span class="font-medium text-gray-700 dark:text-gray-300">Permissions:</span> ${token.resource_scopes.map(escapeHtml).join(", ")}</div>` : ""}
     </div>

     <div class="flex space-x-2 ml-4">
      <button
       onclick="viewTokenUsage('${token.id}')"
       class="px-3 py-1 text-sm font-medium text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 border border-blue-300 dark:border-blue-600 hover:border-blue-500 dark:hover:border-blue-400 rounded-md"
      >
       Usage Stats
      </button>
      <button
       onclick="revokeToken('${token.id}', '${escapeHtml(token.name)}')"
       class="px-3 py-1 text-sm font-medium text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300 border border-red-300 dark:border-red-600 hover:border-red-500 dark:hover:border-blue-400 rounded-md"
      >
       Revoke
      </button>
     </div>
    </div>
   </div>
  `;
  });

  listEl.innerHTML = html;
}

/**
 * Set up create token form handling (personal + team)
 */
function setupCreateTokenForm() {
  const personalForm = safeGetElement("create-token-form");
  if (personalForm && !personalForm.hasAttribute("data-setup")) {
    personalForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      await createToken(personalForm);
    });
    personalForm.setAttribute("data-setup", "true");
  }

  const teamForm = safeGetElement("create-team-token-form");
  if (teamForm && !teamForm.hasAttribute("data-setup")) {
    teamForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      await createTeamToken(teamForm);
    });
    teamForm.setAttribute("data-setup", "true");
  }
}

/**
 * Wire Team Token create form (kept for compatibility)
 */
function setupCreateTeamTokenForm() {
  const form = safeGetElement("create-team-token-form");
  if (!form) return;

  if (form.dataset.bound === "true") return;
  form.dataset.bound = "true";

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    await createTeamToken(form);
  });
}

/**
 * Wire "Load Team Tokens" button
 */
function setupTeamTokensLoader() {
  const btn = safeGetElement("btn-load-team-tokens");
  const select = safeGetElement("team-token-team-select");

  if (!btn || !select) return;

  btn.addEventListener("click", async () => {
    const teamId = (select.value || "").trim();
    await loadTeamTokensList(teamId);
  });

  select.addEventListener("change", () => {
    const teamTokensList = safeGetElement("team-tokens-list");
    if (!teamTokensList) return;
    if (!select.value) {
      teamTokensList.innerHTML =
        '<p class="text-gray-500 dark:text-gray-400">Select a team and click “Load Team Tokens”.</p>';
    }
  });
}

/**
 * Create a new personal API token
 */
async function createToken(form) {
  const formData = new FormData(form);
  const submitButton = form.querySelector('button[type="submit"]');
  const originalText = submitButton.textContent;

  try {
    submitButton.textContent = "Creating...";
    submitButton.disabled = true;

    const payload = {
      name: (formData.get("name") || "").trim(),
      description: (formData.get("description") || "").trim() || null,
      expires_in_days: formData.get("expires_in_days")
        ? parseInt(formData.get("expires_in_days"), 10)
        : null,
      tags: [],
    };

    const scope = buildScopeFromFormData(formData, { requirePermissions: false });
    if (scope) payload.scope = scope;

    const response = await fetchWithTimeout(tokensEndpoints().personalCreate(), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await getAuthToken()}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const error = await safeJson(response);
      throw new Error(error?.detail || `Failed to create token: ${response.status}`);
    }

    const result = await response.json();
    showTokenCreatedModal(result);

    form.reset();
    await loadTokensList();

    showNotification("Token created successfully", "success");
  } catch (error) {
    console.error("Error creating token:", error);
    showNotification(`Error creating token: ${error.message}`, "error");
  } finally {
    submitButton.textContent = originalText;
    submitButton.disabled = false;
  }
}

/**
 * Create a new TEAM API token
 */
async function createTeamToken(form) {
  const formData = new FormData(form);
  const submitButton = form.querySelector('button[type="submit"]');
  const originalText = submitButton ? submitButton.textContent : "Create Team Token";

  const teamSelect = safeGetElement("team-token-team-select");
  const teamId = teamSelect ? (teamSelect.value || "").trim() : "";
  if (!teamId) {
    showNotification("Select a team first to create a team token.", "error");
    return;
  }

  try {
    if (submitButton) {
      submitButton.textContent = "Creating...";
      submitButton.disabled = true;
    }

    const serverIdRaw = (formData.get("server_id") || "").trim();

    const permissions = (formData.get("permissions") || "")
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);

    const ipRestrictions = (formData.get("ip_restrictions") || "")
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);

    if (!permissions.length) {
      throw new Error("Team token requires at least one permission (e.g., tools.read).");
    }

    const payload = {
      name: (formData.get("name") || "").trim(),
      description: (formData.get("description") || "").trim() || null,
      expires_in_days: formData.get("expires_in_days")
        ? parseInt(formData.get("expires_in_days"), 10)
        : null,
      tags: [],
      scope: {
        server_id: serverIdRaw || null,
        permissions,
        ip_restrictions: ipRestrictions,
        time_restrictions: {},
        usage_limits: {},
      },
    };

    const response = await fetchWithTimeout(tokensEndpoints().teamCreate(teamId), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await getAuthToken()}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to create team token: ${response.status}`);
    }

    const result = await response.json();

    if (typeof showTokenCreatedModal === "function") {
      showTokenCreatedModal(result);
    } else {
      console.warn("showTokenCreatedModal not found; token will not be displayed.");
      showNotification("Team token created. (Token modal missing in JS)", "success");
    }

    await loadTeamTokensList(teamId);

    showNotification("Team token created successfully", "success");
    form.reset();
  } catch (error) {
    console.error("Error creating team token:", error);
    showNotification(`Error creating team token: ${error.message}`, "error");
  } finally {
    if (submitButton) {
      submitButton.textContent = originalText;
      submitButton.disabled = false;
    }
  }
}

/**
 * Revoke a token (works for both personal + team tokens + admin mode)
 */
async function revokeToken(tokenId, tokenName) {
  if (!confirm(`Are you sure you want to revoke the token "${tokenName}"? This action cannot be undone.`)) {
    return;
  }

  try {
    const response = await fetchWithTimeout(
      tokensEndpoints().personalRevoke(tokenId),
      {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${await getAuthToken()}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          reason: "Revoked by user via admin interface",
        }),
      },
    );

    if (!response.ok) {
      const error = await safeJson(response);
      throw new Error(error?.detail || `Failed to revoke token: ${response.status}`);
    }

    showNotification("Token revoked successfully", "success");

    const teamSection = safeGetElement("tokens-section-team");
    const teamVisible = teamSection && !teamSection.classList.contains("hidden");
    if (teamVisible) {
      const teamSelect = safeGetElement("team-token-team-select");
      const teamId = teamSelect ? (teamSelect.value || "").trim() : "";
      if (teamId) {
        await loadTeamTokensList(teamId);
        return;
      }
    }

    await loadTokensList();
  } catch (error) {
    console.error("Error revoking token:", error);
    showNotification(`Error revoking token: ${error.message}`, "error");
  }
}

/**
 * View token usage statistics (works for both personal + team tokens + admin mode)
 */
async function viewTokenUsage(tokenId) {
  try {
    const response = await fetchWithTimeout(
      tokensEndpoints().personalUsage(tokenId),
      {
        headers: {
          Authorization: `Bearer ${await getAuthToken()}`,
          "Content-Type": "application/json",
        },
      },
    );

    if (!response.ok) {
      const err = await safeJson(response);
      throw new Error(err?.detail || `Failed to load usage stats: ${response.status}`);
    }

    const stats = await response.json();
    showUsageStatsModal(stats);
  } catch (error) {
    console.error("Error loading usage stats:", error);
    showNotification(`Error loading usage stats: ${error.message}`, "error");
  }
}

/**
 * Helper: build scope object from form data
 */
function buildScopeFromFormData(formData, { requirePermissions }) {
  const serverId = (formData.get("server_id") || "").trim();
  const ipRaw = (formData.get("ip_restrictions") || "").trim();
  const permRaw = (formData.get("permissions") || "").trim();

  const ip_restrictions = ipRaw
    ? ipRaw.split(",").map((ip) => ip.trim()).filter(Boolean)
    : [];

  const permissions = permRaw
    ? permRaw.split(",").map((p) => p.trim()).filter(Boolean)
    : [];

  if (requirePermissions && permissions.length === 0) {
    throw new Error("Permissions are required for team tokens.");
  }

  const hasAny =
    !!serverId ||
    ip_restrictions.length > 0 ||
    permissions.length > 0;

  if (!hasAny && !requirePermissions) {
    return null;
  }

  return {
    server_id: serverId || null,
    permissions,
    ip_restrictions,
    time_restrictions: {},
    usage_limits: {},
  };
}

/**
 * Helper: safe json parsing
 */
async function safeJson(response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

/**
 * Get auth token from storage or user input
 */
async function getAuthToken() {
  let token = getCookie("jwt_token");
  if (!token) token = getCookie("token");
  if (!token) token = localStorage.getItem("auth_token");
  return token || "";
}

/**
 * Init: call this once when admin UI loads
 */
function initTokenUI() {
  setupCreateTokenForm();
  setupCreateTeamTokenForm();
  setupTeamTokensLoader();

  if (safeGetElement("tokens-list")) {
    loadTokensList();
  }

  const teamTokensList = safeGetElement("team-tokens-list");
  if (teamTokensList) {
    teamTokensList.innerHTML =
      '<p class="text-gray-500 dark:text-gray-400">Select a team and click “Load Team Tokens”.</p>';
  }
}

// Expose token management functions to global scope
window.loadTokensList = loadTokensList;
window.setupCreateTokenForm = setupCreateTokenForm;
window.createToken = createToken;
window.createTeamToken = createTeamToken;
window.revokeToken = revokeToken;
window.viewTokenUsage = viewTokenUsage;
window.copyToClipboard = copyToClipboard;
window.showTokenCreatedModal = showTokenCreatedModal;
window.showUsageStatsModal = showUsageStatsModal;
window.loadTeamTokensList = loadTeamTokensList;



// ===================================================================
// USER MANAGEMENT FUNCTIONS
// ===================================================================

// ===================================================================
// USER MANAGEMENT FUNCTIONS (FIXED EDIT MODAL WIRING)
// ===================================================================

function showUserEditModal(userEmail) {
  const modal = document.getElementById("user-edit-modal");
  if (!modal) return;

  modal.style.display = "block";
  modal.classList.remove("hidden");

  // Optional: store current email for save actions / debugging
  if (userEmail) modal.setAttribute("data-user-email", userEmail);
}

function hideUserEditModal() {
  const modal = document.getElementById("user-edit-modal");
  if (!modal) return;

  modal.style.display = "none";
  modal.classList.add("hidden");
  modal.removeAttribute("data-user-email");
}

// 1) Close modal when clicking outside
document.addEventListener("DOMContentLoaded", function () {
  const userModal = document.getElementById("user-edit-modal");
  if (userModal) {
    userModal.addEventListener("click", function (event) {
      if (event.target === userModal) hideUserEditModal();
    });
  }

  const teamModal = document.getElementById("team-edit-modal");
  if (teamModal) {
    teamModal.addEventListener("click", function (event) {
      if (event.target === teamModal) hideTeamEditModal();
    });
  }

  // 2) ✅ Show user modal AFTER the edit fragment is swapped into the modal target
  document.body.addEventListener("htmx:afterSwap", function (event) {
    // Change this ID to whatever your hx-target is for the edit form
    // Example: hx-target="#user-edit-modal-content"
    const target = event.detail && event.detail.target;

    if (!target) return;

    // If the swap happened inside the user edit modal content area, open the modal
    if (target.id === "user-edit-modal-content" || target.closest?.("#user-edit-modal-content")) {
      // Try to infer email from data attribute if present
      const modal = document.getElementById("user-edit-modal");
      const email = modal?.getAttribute("data-user-email") || null;
      showUserEditModal(email);
    }
  });

  // 3) ✅ Event delegation: Edit buttons work even for HTMX-inserted rows
  // Add data-user-email="..." to your edit button/link OR keep it on row container.
  document.body.addEventListener("click", function (e) {
    const btn = e.target.closest?.("[data-action='user-edit']");
    if (!btn) return;

    // If it's a link or button inside a form, prevent accidental navigation/submission
    e.preventDefault();

    const email = btn.getAttribute("data-user-email") || btn.closest?.("[data-user-email]")?.getAttribute("data-user-email");
    if (!email) {
      // Still open modal, but you likely want to add data-user-email to the button
      showUserEditModal();
      return;
    }

    // If your edit is HTMX-driven, the button should already have hx-get + hx-target.
    // But opening the modal immediately improves perceived performance.
    showUserEditModal(email);
  });
});

// Expose user modal functions to global scope
window.showUserEditModal = showUserEditModal;
window.hideUserEditModal = hideUserEditModal;


// Team edit modal functions
async function showTeamEditModal(teamId) {
    // Get the root path by extracting it from the current pathname
    let rootPath = window.location.pathname;
    const adminIndex = rootPath.lastIndexOf("/admin");
    if (adminIndex !== -1) {
        rootPath = rootPath.substring(0, adminIndex);
    } else {
        rootPath = "";
    }

    // Construct the full URL - ensure it starts with /
    const url = (rootPath || "") + "/admin/teams/" + teamId + "/edit";

    // Load the team edit form via HTMX
    fetch(url, {
        method: "GET",
        headers: {
            Authorization: "Bearer " + (await getAuthToken()),
        },
    })
        .then((response) => response.text())
        .then((html) => {
            document.getElementById("team-edit-modal-content").innerHTML = html;
            document
                .getElementById("team-edit-modal")
                .classList.remove("hidden");
        })
        .catch((error) => {
            console.error("Error loading team edit form:", error);
        });
}

function hideTeamEditModal() {
    document.getElementById("team-edit-modal").classList.add("hidden");
}

// Expose team modal functions to global scope
window.showTeamEditModal = showTeamEditModal;
window.hideTeamEditModal = hideTeamEditModal;

// Team member management functions
function showAddMemberForm(teamId) {
    const form = document.getElementById("add-member-form-" + teamId);
    if (form) {
        form.classList.remove("hidden");
    }
}

function hideAddMemberForm(teamId) {
    const form = document.getElementById("add-member-form-" + teamId);
    if (form) {
        form.classList.add("hidden");
        // Reset form
        const formElement = form.querySelector("form");
        if (formElement) {
            formElement.reset();
        }
    }
}

// Expose team member management functions to global scope
window.showAddMemberForm = showAddMemberForm;
window.hideAddMemberForm = hideAddMemberForm;

// Logs refresh function
function refreshLogs() {
    const logsSection = document.getElementById("logs");
    if (logsSection && typeof window.htmx !== "undefined") {
        // Trigger HTMX refresh on the logs section
        window.htmx.trigger(logsSection, "refresh");
    }
}

// Expose logs functions to global scope
window.refreshLogs = refreshLogs;

// User edit modal functions (already defined above)
// Functions are already exposed to global scope

// Team permissions functions are implemented in the admin.html template
// Remove placeholder functions to avoid overriding template functionality

async function initializePermissionsPanel(force = false) {
  try {
    window.__permAuditState = window.__permAuditState || { initialized: false };
    if (window.__permAuditState.initialized && !force) return;

    await Promise.allSettled([
      loadAuditUserDropdowns(),
      loadAuditPermissionsDropdown(),
    ]);

    // ✅ Enable click-to-toggle multi select
    enableClickToggleMultiSelect("perm-audit-check-perms", "perm-audit-selected-count");

    window.__permAuditState.initialized = true;
  } catch (e) {
    console.error("PERM AUDIT: initializePermissionsPanel failed:", e);
  }
}


// Permission functions are implemented in admin.html template - don't override them
window.initializePermissionsPanel = initializePermissionsPanel;

// // ===================================================================
// // TEAM DISCOVERY AND SELF-SERVICE FUNCTIONS
// // ===================================================================

// /**
//  * Load and display public teams that the user can join
//  */
// async function loadPublicTeams() {
//     const container = safeGetElement("public-teams-list");
//     if (!container) {
//         console.error("Public teams list container not found");
//         return;
//     }

//     // Show loading state
//     container.innerHTML =
//         '<div class="animate-pulse text-gray-500 dark:text-gray-400">Loading public teams...</div>';

//     try {
//         const response = await fetchWithTimeout(
//             `${window.ROOT_PATH || ""}/teams/discover`,
//             {
//                 headers: {
//                     Authorization: `Bearer ${await getAuthToken()}`,
//                     "Content-Type": "application/json",
//                 },
//             },
//         );
//         if (!response.ok) {
//             throw new Error(`Failed to load teams: ${response.status}`);
//         }

//         const teams = await response.json();
//         displayPublicTeams(teams);
//     } catch (error) {
//         console.error("Error loading public teams:", error);
//         container.innerHTML = `
//             <div class="bg-red-50 dark:bg-red-900 border border-red-200 dark:border-red-700 rounded-md p-4">
//                 <div class="flex">
//                     <div class="flex-shrink-0">
//                         <svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
//                             <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clip-rule="evenodd" />
//                         </svg>
//                     </div>
//                     <div class="ml-3">
//                         <h3 class="text-sm font-medium text-red-800 dark:text-red-200">
//                             Failed to load public teams
//                         </h3>
//                         <div class="mt-2 text-sm text-red-700 dark:text-red-300">
//                             ${escapeHtml(error.message)}
//                         </div>
//                     </div>
//                 </div>
//             </div>
//         `;
//     }
// }

// /**
//  * Display public teams in the UI
//  * @param {Array} teams - Array of team objects
//  */
// function displayPublicTeams(teams) {
//     const container = safeGetElement("public-teams-list");
//     if (!container) {
//         return;
//     }

//     if (!teams || teams.length === 0) {
//         container.innerHTML = `
//             <div class="text-center py-8">
//                 <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
//                     <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.83-1M17 20H7m10 0v-2c0-1.09-.29-2.11-.83-3M7 20v2m0-2v-2a3 3 0 011.87-2.77m0 0A3 3 0 017 12m0 0a3 3 0 013-3m-3 3h6.4M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
//                 </svg>
//                 <h3 class="mt-2 text-sm font-medium text-gray-900 dark:text-gray-100">No public teams found</h3>
//                 <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">There are no public teams available to join at the moment.</p>
//             </div>
//         `;
//         return;
//     }

//     // Create teams grid
//     const teamsHtml = teams
//         .map(
//             (team) => `
//         <div class="bg-white dark:bg-gray-700 shadow rounded-lg p-6 hover:shadow-lg transition-shadow">
//             <div class="flex items-center justify-between">
//                 <h3 class="text-lg font-medium text-gray-900 dark:text-white">
//                     ${escapeHtml(team.name)}
//                 </h3>
//                 <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
//                     Public
//                 </span>
//             </div>

//             ${
//                 team.description
//                     ? `
//                 <p class="mt-2 text-sm text-gray-600 dark:text-gray-300">
//                     ${escapeHtml(team.description)}
//                 </p>
//             `
//                     : ""
//             }

//             <div class="mt-4 flex items-center justify-between">
//                 <div class="flex items-center text-sm text-gray-500 dark:text-gray-400">
//                     <svg class="flex-shrink-0 mr-1.5 h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
//                         <path d="M9 6a3 3 0 11-6 0 3 3 0 016 0zM17 6a3 3 0 11-6 0 3 3 0 016 0zM12.93 17c.046-.327.07-.66.07-1a6.97 6.97 0 00-1.5-4.33A5 5 0 0119 16v1h-6.07zM6 11a5 5 0 015 5v1H1v-1a5 5 0 015-5z"/>
//                     </svg>
//                     ${team.member_count} members
//                 </div>
//                 <button
//                     onclick="requestToJoinTeam('${escapeHtml(team.id)}')"
//                     class="px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
//                 >
//                     Request to Join
//                 </button>
//             </div>
//         </div>
//     `,
//         )
//         .join("");

//     container.innerHTML = `
//         <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
//             ${teamsHtml}
//         </div>
//     `;
// }

// /**
//  * Request to join a public team
//  * @param {string} teamId - ID of the team to join
//  */
// async function requestToJoinTeam(teamId) {
//     if (!teamId) {
//         console.error("Team ID is required");
//         return;
//     }

//     // Show confirmation dialog
//     const message = prompt("Optional: Enter a message to the team owners:");

//     try {
//         const response = await fetchWithTimeout(
//             `${window.ROOT_PATH || ""}/teams/${teamId}/join`,
//             {
//                 method: "POST",
//                 headers: {
//                     Authorization: `Bearer ${await getAuthToken()}`,
//                     "Content-Type": "application/json",
//                 },
//                 body: JSON.stringify({
//                     message: message || null,
//                 }),
//             },
//         );

//         if (!response.ok) {
//             const errorData = await response.json().catch(() => null);
//             throw new Error(
//                 errorData?.detail ||
//                     `Failed to request join: ${response.status}`,
//             );
//         }

//         const result = await response.json();

//         // Show success message
//         showSuccessMessage(
//             `Join request sent to ${result.team_name}! Team owners will review your request.`,
//         );

//         // Refresh the public teams list
//         setTimeout(loadPublicTeams, 1000);
//     } catch (error) {
//         console.error("Error requesting to join team:", error);
//         showErrorMessage(`Failed to send join request: ${error.message}`);
//     }
// }

// /**
//  * Leave a team
//  * @param {string} teamId - ID of the team to leave
//  * @param {string} teamName - Name of the team (for confirmation)
//  */
// async function leaveTeam(teamId, teamName) {
//     if (!teamId) {
//         console.error("Team ID is required");
//         return;
//     }

//     // Show confirmation dialog
//     const confirmed = confirm(
//         `Are you sure you want to leave the team "${teamName}"? This action cannot be undone.`,
//     );
//     if (!confirmed) {
//         return;
//     }

//     try {
//         const response = await fetchWithTimeout(
//             `${window.ROOT_PATH || ""}/teams/${teamId}/leave`,
//             {
//                 method: "DELETE",
//                 headers: {
//                     Authorization: `Bearer ${await getAuthToken()}`,
//                     "Content-Type": "application/json",
//                 },
//             },
//         );

//         if (!response.ok) {
//             const errorData = await response.json().catch(() => null);
//             throw new Error(
//                 errorData?.detail || `Failed to leave team: ${response.status}`,
//             );
//         }

//         await response.json();

//         // Show success message
//         showSuccessMessage(`Successfully left ${teamName}`);

//         // Refresh teams list
//         const teamsList = safeGetElement("teams-list");
//         if (teamsList && window.htmx) {
//             window.htmx.trigger(teamsList, "load");
//         }

//         // Refresh team selector if available
//         if (typeof updateTeamContext === "function") {
//             // Force reload teams data
//             setTimeout(() => {
//                 window.location.reload();
//             }, 1500);
//         }
//     } catch (error) {
//         console.error("Error leaving team:", error);
//         showErrorMessage(`Failed to leave team: ${error.message}`);
//     }
// }

// /**
//  * Approve a join request
//  * @param {string} teamId - ID of the team
//  * @param {string} requestId - ID of the join request
//  */
// async function approveJoinRequest(teamId, requestId) {
//     if (!teamId || !requestId) {
//         console.error("Team ID and request ID are required");
//         return;
//     }

//     try {
//         const response = await fetchWithTimeout(
//             `${window.ROOT_PATH || ""}/teams/${teamId}/join-requests/${requestId}/approve`,
//             {
//                 method: "POST",
//                 headers: {
//                     Authorization: `Bearer ${await getAuthToken()}`,
//                     "Content-Type": "application/json",
//                 },
//             },
//         );

//         if (!response.ok) {
//             const errorData = await response.json().catch(() => null);
//             throw new Error(
//                 errorData?.detail ||
//                     `Failed to approve join request: ${response.status}`,
//             );
//         }

//         const result = await response.json();

//         // Show success message
//         showSuccessMessage(
//             `Join request approved! ${result.user_email} is now a member.`,
//         );

//         // Refresh teams list
//         const teamsList = safeGetElement("teams-list");
//         if (teamsList && window.htmx) {
//             window.htmx.trigger(teamsList, "load");
//         }
//     } catch (error) {
//         console.error("Error approving join request:", error);
//         showErrorMessage(`Failed to approve join request: ${error.message}`);
//     }
// }

// /**
//  * Reject a join request
//  * @param {string} teamId - ID of the team
//  * @param {string} requestId - ID of the join request
//  */
// async function rejectJoinRequest(teamId, requestId) {
//     if (!teamId || !requestId) {
//         console.error("Team ID and request ID are required");
//         return;
//     }

//     const confirmed = confirm(
//         "Are you sure you want to reject this join request?",
//     );
//     if (!confirmed) {
//         return;
//     }

//     try {
//         const response = await fetchWithTimeout(
//             `${window.ROOT_PATH || ""}/teams/${teamId}/join-requests/${requestId}`,
//             {
//                 method: "DELETE",
//                 headers: {
//                     Authorization: `Bearer ${await getAuthToken()}`,
//                     "Content-Type": "application/json",
//                 },
//             },
//         );

//         if (!response.ok) {
//             const errorData = await response.json().catch(() => null);
//             throw new Error(
//                 errorData?.detail ||
//                     `Failed to reject join request: ${response.status}`,
//             );
//         }

//         // Show success message
//         showSuccessMessage("Join request rejected.");

//         // Refresh teams list
//         const teamsList = safeGetElement("teams-list");
//         if (teamsList && window.htmx) {
//             window.htmx.trigger(teamsList, "load");
//         }
//     } catch (error) {
//         console.error("Error rejecting join request:", error);
//         showErrorMessage(`Failed to reject join request: ${error.message}`);
//     }
// }

// Expose team functions to global scope
window.loadPublicTeams = loadPublicTeams;
window.requestToJoinTeam = requestToJoinTeam;
window.leaveTeam = leaveTeam;
window.approveJoinRequest = approveJoinRequest;
window.rejectJoinRequest = rejectJoinRequest;

/**
 * Validate password match in user edit form
 */
function validatePasswordMatch() {
    const passwordField = document.getElementById("password-field");
    const confirmPasswordField = document.getElementById(
        "confirm-password-field",
    );
    const messageElement = document.getElementById("password-match-message");
    const submitButton = document.querySelector(
        '#user-edit-modal-content button[type="submit"]',
    );

    if (!passwordField || !confirmPasswordField || !messageElement) {
        return;
    }

    const password = passwordField.value;
    const confirmPassword = confirmPasswordField.value;

    // Only show validation if both fields have content or if confirm field has content
    if (
        (password.length > 0 || confirmPassword.length > 0) &&
        password !== confirmPassword
    ) {
        messageElement.classList.remove("hidden");
        confirmPasswordField.classList.add("border-red-500");
        if (submitButton) {
            submitButton.disabled = true;
            submitButton.classList.add("opacity-50", "cursor-not-allowed");
        }
    } else {
        messageElement.classList.add("hidden");
        confirmPasswordField.classList.remove("border-red-500");
        if (submitButton) {
            submitButton.disabled = false;
            submitButton.classList.remove("opacity-50", "cursor-not-allowed");
        }
    }
}

// Expose password validation function to global scope
window.validatePasswordMatch = validatePasswordMatch;

// ===================================================================
// SELECTIVE IMPORT FUNCTIONS
// ===================================================================

/**
 * Display import preview with selective import options
 */
function displayImportPreview(preview) {
    console.log("📋 Displaying import preview:", preview);

    // Find or create preview container
    let previewContainer = document.getElementById("import-preview-container");
    if (!previewContainer) {
        previewContainer = document.createElement("div");
        previewContainer.id = "import-preview-container";
        previewContainer.className = "mt-6 border-t pt-6";

        // Insert after import options in the import section
        const importSection =
            document.querySelector("#import-drop-zone").parentElement
                .parentElement;
        importSection.appendChild(previewContainer);
    }

    previewContainer.innerHTML = `
        <h4 class="text-lg font-medium text-gray-900 dark:text-white mb-4">
            📋 Selective Import - Choose What to Import
        </h4>

        <!-- Summary -->
        <div class="bg-blue-50 dark:bg-blue-900 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mb-6">
            <div class="flex items-center">
                <div class="ml-3">
                    <h3 class="text-sm font-medium text-blue-800 dark:text-blue-200">
                        Found ${preview.summary.total_items} items in import file
                    </h3>
                    <div class="mt-1 text-sm text-blue-600 dark:text-blue-300">
                        ${Object.entries(preview.summary.by_type)
                            .map(([type, count]) => `${type}: ${count}`)
                            .join(", ")}
                    </div>
                </div>
            </div>
        </div>

        <!-- Selection Controls -->
        <div class="flex justify-between items-center mb-4">
            <div class="space-x-4">
                <button onclick="selectAllItems()"
                        class="text-sm text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 underline">
                    Select All
                </button>
                <button onclick="selectNoneItems()"
                        class="text-sm text-gray-600 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-300 underline">
                    Select None
                </button>
                <button onclick="selectOnlyCustom()"
                        class="text-sm text-green-600 dark:text-green-400 hover:text-green-800 dark:hover:text-green-300 underline">
                    Custom Items Only
                </button>
            </div>

            <div class="text-sm text-gray-500 dark:text-gray-400">
                <span id="selection-count">0 items selected</span>
            </div>
        </div>

        <!-- Gateway Bundles -->
        ${
            Object.keys(preview.bundles || {}).length > 0
                ? `
            <div class="mb-6">
                <h5 class="text-md font-medium text-gray-900 dark:text-white mb-3">
                    🌐 Gateway Bundles (Gateway + Auto-discovered Items)
                </h5>
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    ${Object.entries(preview.bundles)
                        .map(
                            ([gatewayName, bundle]) => `
                        <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:bg-gray-50 dark:hover:bg-gray-750">
                            <label class="flex items-start cursor-pointer">
                                <input type="checkbox"
                                       class="gateway-checkbox mt-1 mr-3"
                                       data-gateway="${gatewayName}"
                                       onchange="updateSelectionCount()">
                                <div class="flex-1">
                                    <div class="font-medium text-gray-900 dark:text-white">
                                        ${bundle.gateway.name}
                                    </div>
                                    <div class="text-sm text-gray-500 dark:text-gray-400 mb-2">
                                        ${bundle.gateway.description || "No description"}
                                    </div>
                                    <div class="text-xs text-blue-600 dark:text-blue-400">
                                        Bundle includes: ${bundle.total_items} items
                                        (${Object.entries(bundle.items)
                                            .filter(
                                                ([type, items]) =>
                                                    items.length > 0,
                                            )
                                            .map(
                                                ([type, items]) =>
                                                    `${items.length} ${type}`,
                                            )
                                            .join(", ")})
                                    </div>
                                </div>
                            </label>
                        </div>
                    `,
                        )
                        .join("")}
                </div>
            </div>
        `
                : ""
        }

        <!-- Custom Items by Type -->
        ${Object.entries(preview.items || {})
            .map(([entityType, items]) => {
                const customItems = items.filter((item) => item.is_custom);
                return customItems.length > 0
                    ? `
                <div class="mb-6">
                    <h5 class="text-md font-medium text-gray-900 dark:text-white mb-3 capitalize">
                        🛠️ Custom ${entityType}
                    </h5>
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                        ${customItems
                            .map(
                                (item) => `
                            <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-3 hover:bg-gray-50 dark:hover:bg-gray-750 ${item.conflicts_with ? "border-orange-300 dark:border-orange-700 bg-orange-50 dark:bg-orange-900" : ""}">
                                <label class="flex items-start cursor-pointer">
                                    <input type="checkbox"
                                           class="item-checkbox mt-1 mr-3"
                                           data-type="${entityType}"
                                           data-id="${item.id}"
                                           onchange="updateSelectionCount()">
                                    <div class="flex-1">
                                        <div class="text-sm font-medium text-gray-900 dark:text-white">
                                            ${item.name}
                                            ${
                                                item.conflicts_with
                                                    ? '<span class="text-orange-600 text-xs ml-1">⚠️ Conflict</span>'
                                                    : ""
                                            }
                                        </div>
                                        <div class="text-xs text-gray-500 dark:text-gray-400">
                                            ${item.description || `Custom ${entityType} item`}
                                        </div>
                                    </div>
                                </label>
                            </div>
                        `,
                            )
                            .join("")}
                    </div>
                </div>
            `
                    : "";
            })
            .join("")}

        <!-- Conflicts Warning -->
        ${
            Object.keys(preview.conflicts || {}).length > 0
                ? `
            <div class="mb-6">
                <div class="bg-orange-50 dark:bg-orange-900 border border-orange-200 dark:border-orange-800 rounded-lg p-4">
                    <div class="flex items-start">
                        <div class="flex-shrink-0">
                            <svg class="h-5 w-5 text-orange-400" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/>
                            </svg>
                        </div>
                        <div class="ml-3">
                            <h3 class="text-sm font-medium text-orange-800 dark:text-orange-200">
                                Naming conflicts detected
                            </h3>
                            <div class="mt-1 text-sm text-orange-600 dark:text-orange-300">
                                Some items have the same names as existing items. Use conflict strategy to resolve.
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `
                : ""
        }

        <!-- Action Buttons -->
        <div class="flex justify-between pt-6 border-t border-gray-200 dark:border-gray-700">
            <button onclick="resetImportSelection()"
                    class="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700">
                🔄 Reset Selection
            </button>

            <div class="space-x-3">
                <button onclick="handleSelectiveImport(true)"
                        class="px-4 py-2 text-sm font-medium text-blue-700 dark:text-blue-300 bg-blue-50 dark:bg-blue-900 border border-blue-200 dark:border-blue-800 rounded-md hover:bg-blue-100 dark:hover:bg-blue-800">
                    🧪 Preview Selected
                </button>
                <button onclick="handleSelectiveImport(false)"
                        class="px-4 py-2 text-sm font-medium text-white bg-green-600 border border-transparent rounded-md hover:bg-green-700">
                    ✅ Import Selected Items
                </button>
            </div>
        </div>
    `;

    // Store preview data and show preview section
    window.currentImportPreview = preview;
    updateSelectionCount();
}

/**
 * Handle selective import based on user selections
 */
async function handleSelectiveImport(dryRun = false) {
    console.log(`🎯 Starting selective import (dry_run=${dryRun})`);

    if (!window.currentImportData) {
        showNotification("❌ Please select an import file first", "error");
        return;
    }

    try {
        showImportProgress(true);

        // Collect user selections
        const selectedEntities = collectUserSelections();

        if (Object.keys(selectedEntities).length === 0) {
            showNotification(
                "❌ Please select at least one item to import",
                "warning",
            );
            showImportProgress(false);
            return;
        }

        const conflictStrategy =
            document.getElementById("import-conflict-strategy")?.value ||
            "update";
        const rekeySecret =
            document.getElementById("import-rekey-secret")?.value || null;

        const requestData = {
            import_data: window.currentImportData,
            conflict_strategy: conflictStrategy,
            dry_run: dryRun,
            rekey_secret: rekeySecret,
            selectedEntities,
        };

        console.log("🎯 Selected entities for import:", selectedEntities);

        const response = await fetch(
            (window.ROOT_PATH || "") + "/admin/import/configuration",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${await getAuthToken()}`,
                },
                body: JSON.stringify(requestData),
            },
        );

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(
                errorData.detail || `Import failed: ${response.statusText}`,
            );
        }

        const result = await response.json();
        displayImportResults(result, dryRun);

        if (!dryRun) {
            refreshCurrentTabData();
            showNotification(
                "✅ Selective import completed successfully",
                "success",
            );
        } else {
            showNotification("✅ Import preview completed", "success");
        }
    } catch (error) {
        console.error("Selective import error:", error);
        showNotification(`❌ Import failed: ${error.message}`, "error");
    } finally {
        showImportProgress(false);
    }
}

/**
 * Collect user selections for selective import
 */
function collectUserSelections() {
    const selections = {};

    // Collect gateway selections
    document
        .querySelectorAll(".gateway-checkbox:checked")
        .forEach((checkbox) => {
            const gatewayName = checkbox.dataset.gateway;
            if (!selections.gateways) {
                selections.gateways = [];
            }
            selections.gateways.push(gatewayName);
        });

    // Collect individual item selections
    document.querySelectorAll(".item-checkbox:checked").forEach((checkbox) => {
        const entityType = checkbox.dataset.type;
        const itemId = checkbox.dataset.id;
        if (!selections[entityType]) {
            selections[entityType] = [];
        }
        selections[entityType].push(itemId);
    });

    return selections;
}

/**
 * Update selection count display
 */
function updateSelectionCount() {
    const gatewayCount = document.querySelectorAll(
        ".gateway-checkbox:checked",
    ).length;
    const itemCount = document.querySelectorAll(
        ".item-checkbox:checked",
    ).length;
    const totalCount = gatewayCount + itemCount;

    const countElement = document.getElementById("selection-count");
    if (countElement) {
        countElement.textContent = `${totalCount} items selected (${gatewayCount} gateways, ${itemCount} individual items)`;
    }
}

/**
 * Select all items
 */
function selectAllItems() {
    document
        .querySelectorAll(".gateway-checkbox, .item-checkbox")
        .forEach((checkbox) => {
            checkbox.checked = true;
        });
    updateSelectionCount();
}

/**
 * Select no items
 */
function selectNoneItems() {
    document
        .querySelectorAll(".gateway-checkbox, .item-checkbox")
        .forEach((checkbox) => {
            checkbox.checked = false;
        });
    updateSelectionCount();
}

/**
 * Select only custom items (not gateway items)
 */
function selectOnlyCustom() {
    document.querySelectorAll(".gateway-checkbox").forEach((checkbox) => {
        checkbox.checked = false;
    });
    document.querySelectorAll(".item-checkbox").forEach((checkbox) => {
        checkbox.checked = true;
    });
    updateSelectionCount();
}

/**
 * Reset import selection
 */
function resetImportSelection() {
    const previewContainer = document.getElementById(
        "import-preview-container",
    );
    if (previewContainer) {
        previewContainer.remove();
    }
    window.currentImportPreview = null;
}

// ===============================
// UI Renderers (JSON → HTML)
// ===============================

function normalizeTeams(rawTeams) {
  return rawTeams.map(t => ({
    ...t,
    is_owner: Boolean(t.is_owner),
    is_member: Boolean(t.is_member),
    is_admin: Boolean(t.is_admin)
  }));
}

function isAdminUserForTeams() {
  return window.__IS_ADMIN__ === true || window.__IS_ADMIN__ === "true";
}

function getMyTeamIdsForAdminView() {
  const teams = Array.isArray(window.USER_TEAMS_DATA) ? window.USER_TEAMS_DATA : [];
  return new Set(teams.map((t) => String(t?.id || "")).filter(Boolean));
}

function splitAdminOwnVsOtherTeams(teams) {
  if (!isAdminUserForTeams()) {
    return { ownTeams: teams, otherTeams: [] };
  }
  const myTeamIds = getMyTeamIdsForAdminView();
  const ownTeams = teams.filter((t) => myTeamIds.has(String(t?.id || "")));
  const otherTeams = teams.filter((t) => !myTeamIds.has(String(t?.id || "")));
  return { ownTeams, otherTeams };
}

function syncAdminOtherTeamsFilterVisibility() {
  const btn = document.getElementById("team-filter-others");
  if (!btn) return;
  if (isAdminUserForTeams()) {
    btn.classList.remove("hidden");
  } else {
    btn.classList.add("hidden");
  }
}

function renderTeamsList(data) {
  console.log("🔥 renderTeamsList called", data);
  const container = document.getElementById('teams-list');
  if (!container) {
    console.error('❌ #teams-list not found in DOM');
    return;
  }

  const { teams, source } = data || {};

  if (!Array.isArray(teams)) {
    console.error('❌ Invalid data passed to renderTeamsList:', data);
    container.innerHTML = `
      <p class="text-red-500 text-center py-6">
        Failed to render teams (invalid data).
      </p>
    `;
    return;
  }

  if (teams.length === 0) {
    container.innerHTML = `
      <p class="col-span-full text-gray-500 text-center py-6">
        No teams found.
      </p>
    `;
    return;
  }

  container.innerHTML = `
    <div class="col-span-full grid w-full grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-6">
      ${teams.map(team => {
        const viewerIsAdmin = isAdminUserForTeams();
        const isOwner = Boolean(team.is_owner);
        const isMember = Boolean(team.is_member);
        const canManageTeam = isOwner || viewerIsAdmin;
        const roleBadge = isOwner
          ? `<span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold bg-[#2561C1]/10 text-[#1f56ad] dark:bg-blue-900/30 dark:text-blue-300">Owner</span>`
          : viewerIsAdmin && source === "teams"
          ? `<span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300">Admin</span>`
          : isMember
          ? `<span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300">Member</span>`
          : source === "discover" && team.can_join
          ? `<span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300">Can Join</span>`
          : `<span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300">Team</span>`;

        const visibility = escapeHtml((team.visibility || "private").toString());
        const visibilityKey = (team.visibility || "private").toString().toLowerCase();
        const visibilityLabel = visibilityKey.charAt(0).toUpperCase() + visibilityKey.slice(1);
        const description = escapeHtml((team.description || "").toString());
        const teamName = escapeHtml((team.name || "").toString());
        const teamId = escapeHtml((team.id || "").toString());
        const memberCount = Number(team.member_count || 0);
        const memberLabel = `${memberCount} ${memberCount === 1 ? "Member" : "Members"}`;
        const canJoin = source === "discover" && team.can_join;
        const alreadyRequested = Boolean(team.requested);
        const visibilityPillClass = visibilityKey === "public"
          ? "border-green-200 bg-green-100 text-green-700 dark:border-green-800 dark:bg-green-900/30 dark:text-green-300"
          : "border-gray-200 bg-gray-100 text-gray-700 dark:border-gray-700 dark:bg-gray-700 dark:text-gray-300";

        return `
        <div class="team-card p-5 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-2xl shadow-sm" data-team-card>
          <div class="relative flex items-start justify-between gap-3">
            <div class="min-w-0">
              <div class="flex items-center gap-2">
                <span class="w-2.5 h-2.5 rounded-full ${canManageTeam ? "bg-green-500" : isMember ? "bg-blue-500" : "bg-yellow-500"} shadow"></span>
                <h4 class="gw-title text-base font-semibold text-gray-900 dark:text-gray-100 truncate">
                  ${teamName}
                </h4>
              </div>
              <div class="mt-2">
                <div class="flex items-center gap-2 text-[11px] text-gray-500 dark:text-gray-400">
                  <span class="uppercase tracking-wide font-semibold">Team ID</span>
                  <span class="gw-pill !px-2 !py-0.5" title="${teamId}">
                    <span class="truncate max-w-[210px] text-[11px]">${teamId}</span>
                  </span>
                </div>
              </div>
            </div>
            ${roleBadge}
          </div>

          <div class="gw-divider my-4"></div>

          <div class="flex flex-wrap items-center gap-2 mb-3">
            <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold border ${visibilityPillClass}">
              ${visibilityLabel}
            </span>
            <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold border border-blue-200 bg-blue-100 text-blue-700 dark:border-blue-800 dark:bg-blue-900/30 dark:text-blue-300">
              ${memberLabel}
            </span>
          </div>

          <div class="text-sm text-gray-700 dark:text-gray-300 leading-relaxed min-h-[2.5rem]">
            ${description || "No description"}
          </div>

          <div class="mt-4 flex justify-end gap-2 flex-wrap">
            ${
              // DISCOVER always uses join request action (even for admin)
              source === "discover"
                ? `
                  <button
                    class="px-3 py-1.5 text-xs font-semibold rounded-xl ${alreadyRequested ? "bg-gray-300 text-gray-700 cursor-not-allowed dark:bg-gray-700 dark:text-gray-300" : "bg-[#2561C1] hover:bg-[#1f56ad] text-white"}"
                    data-team-id="${teamId}"
                    data-team-name="${teamName}"
                    onclick="${alreadyRequested ? "" : "openJoinConfirm(this)"}"
                    ${alreadyRequested ? "disabled" : ""}
                  >
                    ${alreadyRequested ? "Join Request Sent" : "Send Join Request"}
                  </button>
                `
                // OWNER OR ADMIN (non-discover)
                : canManageTeam
                ? `
                    <button
                      class="px-3 py-1.5 text-xs font-semibold rounded-xl text-[#2561C1] hover:bg-blue-50 dark:text-blue-300 dark:hover:bg-blue-900/20 border border-blue-200 dark:border-blue-800"
                      data-team-id="${teamId}"
                      data-team-name="${teamName}"
                      data-is-owner="${isOwner}"
                      data-visibility="${visibility}"
                      onclick="openTeamOptions(this)"
                    >
                      Manage Team
                    </button>

                    <button
                      class="px-3 py-1.5 text-xs font-semibold rounded-xl bg-[#2561C1] hover:bg-[#1f56ad] text-white"
                      data-team-id="${teamId}"
                      onclick="openEditTeamModal(this)"
                    >
                      Edit
                    </button>

                    <button
                      class="px-3 py-1.5 text-xs font-semibold rounded-xl text-red-700 hover:bg-red-50 dark:text-red-300 dark:hover:bg-red-900/20 border border-red-200 dark:border-red-800"
                      data-team-id="${teamId}"
                      data-team-name="${teamName}"
                      onclick="deleteTeamSafe(this)"
                    >
                      Delete
                    </button>
                `
                // MEMBER DEFAULT
                : `
                  <button
                    class="px-3 py-1.5 text-xs font-semibold rounded-xl text-[#2561C1] hover:bg-blue-50 dark:text-blue-300 dark:hover:bg-blue-900/20 border border-blue-200 dark:border-blue-800"
                    onclick="openMemberViewModal('${teamId}')"
                  >
                    View Members
                  </button>
                `
            }
          </div>
        </div>
        `;
      }).join('')}
    </div>
  `;
}

function renderTeamMembersModal(members, canManage, options = {}) {
  const container = document.getElementById('team-edit-modal-content');
  const teamId = options.teamId || "";
  const teamVisibility = (options.visibility || "").toLowerCase();
  const canShowActions = Boolean(canManage && teamId);

  if (!members || members.length === 0) {
    container.innerHTML = `
      <p class="text-gray-500 text-center py-6">
        No team members found.
      </p>
    `;
    return;
  }

  container.innerHTML = `
    <div class="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-2xl shadow-sm p-6">
      <div class="flex justify-between items-center mb-5">
        <h3 class="text-xl font-bold text-gray-900 dark:text-gray-100">Team Members</h3>
        <button
          type="button"
          onclick="document.getElementById('team-edit-modal').classList.add('hidden')"
          class="text-gray-400 hover:text-gray-600 dark:text-gray-300 dark:hover:text-gray-100 text-lg"
        >
          ✕
        </button>
      </div>

      ${
        canShowActions
          ? `
            <div class="mb-4 flex items-center justify-end gap-2">
              ${
                teamVisibility === "public"
                  ? `
                    <button
                      type="button"
                      class="inline-flex items-center gap-2 px-4 py-2 rounded-md text-sm font-semibold text-[#2561C1] hover:bg-blue-50 dark:text-blue-300 dark:hover:bg-blue-900/20 border border-blue-200 dark:border-blue-800"
                      onclick="openJoinRequestsFromManage('${escapeHtml(teamId)}')"
                    >
                      Join Requests
                    </button>
                  `
                  : ""
              }
              <button
                type="button"
                class="inline-flex items-center gap-2 px-4 py-2 rounded-md text-sm font-semibold bg-[#2561C1] hover:bg-[#1f56ad] text-white shadow-sm"
                onclick="openInviteUserModal('${escapeHtml(teamId)}')"
              >
                <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                  stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <circle cx="12" cy="12" r="10"></circle>
                  <path d="M12 8v8M8 12h8"></path>
                </svg>
                Invite User
              </button>
            </div>
          `
          : ""
      }

      <div class="space-y-3">
        ${members.map(m => `
          <div class="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900/40 p-4 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div class="min-w-0">
              <div class="text-sm font-semibold text-gray-900 dark:text-gray-100 truncate">${escapeHtml(m.user_email)}</div>
              <div class="text-xs text-gray-500 dark:text-gray-400 mt-1">Role: ${escapeHtml(m.role)}</div>
            </div>

            <div class="flex items-center gap-2">
              ${
                canManage
                  ? `
                    <select
                      class="rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2 text-sm text-gray-900 dark:text-gray-200"
                      data-user-email="${escapeHtml(m.user_email)}"
                      data-team-id="${escapeHtml(m.team_id)}"
                      data-current-role="${escapeHtml(m.role)}"
                      onchange="changeMemberRole(this)"
                    >
                      <option value="member" ${m.role === 'member' ? 'selected' : ''}>Member</option>
                      <option value="owner" ${m.role === 'owner' ? 'selected' : ''}>Owner</option>
                    </select>
                    <button
                      class="px-3 py-1.5 text-xs font-semibold rounded-xl text-red-700 hover:bg-red-50 dark:text-red-300 dark:hover:bg-red-900/20 border border-red-200 dark:border-red-800"
                      data-user-email="${escapeHtml(m.user_email)}"
                      data-team-id="${escapeHtml(m.team_id)}"
                      onclick="removeTeamMember(this)"
                    >
                      Remove
                    </button>
                  `
                  : `
                    <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300">
                      ${escapeHtml(m.role)}
                    </span>
                  `
              }
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

function renderJoinRequestsModal(requests) {
  const container = document.getElementById('team-join-requests-modal-content');

  if (!requests || requests.length === 0) {
    container.innerHTML = `
      <p class="text-center text-gray-500 py-6">
        No pending join requests.
      </p>
    `;
    return;
  }

  container.innerHTML = `
    <div class="space-y-4">
      ${requests.map(req => `
        <div class="border rounded-md p-4 flex justify-between items-start">

          <!-- LEFT -->
          <div>
            <p class="font-medium text-gray-900 dark:text-white">
              ${req.user_email}
            </p>

            ${req.message ? `
              <p class="text-sm text-gray-600 dark:text-gray-300 mt-1">
                ${req.message}
              </p>
            ` : ''}

            <p class="text-xs text-gray-400 mt-2">
              Requested at: ${new Date(req.requested_at).toLocaleString()}
            </p>
          </div>

          <!-- RIGHT ACTIONS -->
          <div class="flex gap-2">
            <button
              class="px-3 py-1.5 text-xs font-semibold rounded-xl bg-green-600 hover:bg-green-700 text-white"
              data-team-id="${req.team_id}"
              data-request-id="${req.id}"
              onclick="approveJoinRequestSafe(this)"
            >
              Accept
            </button>

            <button
              class="px-3 py-1.5 text-xs font-semibold rounded-xl text-red-700 hover:bg-red-50 dark:text-red-300 dark:hover:bg-red-900/20 border border-red-200 dark:border-red-800"
              data-team-id="${req.team_id}"
              data-request-id="${req.id}"
              onclick="rejectJoinRequestSafe(this)"
            >
              Reject
            </button>
          </div>

        </div>
      `).join('')}
    </div>
  `;
}

function renderInvitationsList(invitations) {
  const container = document.getElementById('teams-list');

  if (!invitations || invitations.length === 0) {
    container.innerHTML = `
      <p class="col-span-full text-gray-500 text-center py-6">
        No pending invitations.
      </p>
    `;
    return;
  }

  container.innerHTML = `
    <div class="col-span-full grid w-full grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-6">
      ${invitations.map(inv => `
        <div class="p-5 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-2xl shadow-sm">
          <div class="flex items-start justify-between gap-3">
            <div class="min-w-0">
              <h4 class="gw-title text-base font-semibold text-gray-900 dark:text-gray-100 truncate">
                ${escapeHtml(inv.team_name || "Team")}
              </h4>
              <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">
                Role: ${escapeHtml(inv.role || "member")}
              </p>
            </div>
            <span class="gw-pill">Invitation</span>
          </div>
          <div class="gw-divider my-4"></div>
          <div class="flex justify-end gap-2">
            <button
              class="px-3 py-1.5 text-xs font-semibold rounded-xl bg-green-600 hover:bg-green-700 text-white"
              onclick="acceptInvitation('${inv.token}')"
            >
              Accept
            </button>

            <button
              class="px-3 py-1.5 text-xs font-semibold rounded-xl text-red-700 hover:bg-red-50 dark:text-red-300 dark:hover:bg-red-900/20 border border-red-200 dark:border-red-800"
              onclick="rejectInvitation('${inv.token}')"
            >
              Reject
            </button>
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

function filterTeams(searchText) {
  const cards = document.querySelectorAll("#teams-list [data-team-card]");
  const query = (searchText || "").toLowerCase().trim();

  cards.forEach((card) => {
    const text = (card.textContent || "").toLowerCase();
    card.style.display = !query || text.includes(query) ? "" : "none";
  });
}

function resolveTeamError(err, fallback = "Operation failed") {
  if (!err) return fallback;
  if (typeof err === "string") return err;
  if (Array.isArray(err.detail)) {
    return err.detail.map((d) => d?.msg || d?.message || JSON.stringify(d)).join("; ");
  }
  return err.detail || err.message || fallback;
}

function acceptInvitation(token) {
  if (!confirm("Accept this invitation?")) return;

  fetch(`${window.ROOT_PATH}/teams/invitations/${token}/accept`, {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + (getCookie('jwt_token') || '')
    }
  })
  .then(res => {
    if (!res.ok) {
      return res.json().then(err => { throw err; });
    }
    return res.json().catch(() => ({}));
  })
  .then(() => {
    showSuccessMessage('Invitation accepted');
    showInvitations();
    loadTeamsByRelationship('all');
  })
  .catch(err => {
    showErrorMessage(resolveTeamError(err, 'Failed to accept invitation'));
  });
}

function rejectInvitation(token) {
  if (!confirm("Reject this invitation?")) return;

  fetch(`${window.ROOT_PATH}/teams/invitations/${token}/reject`, {
    method: 'DELETE',
    headers: {
      'Authorization': 'Bearer ' + (getCookie('jwt_token') || '')
    }
  })
  .then(res => {
    if (!res.ok) {
      return res.json().then(err => { throw err; });
    }
    return res.json().catch(() => ({}));
  })
  .then(() => {
    showSuccessMessage('Invitation rejected');
    showInvitations();
    loadTeamsByRelationship('all');
  })
  .catch(err => {
    showErrorMessage(resolveTeamError(err, 'Failed to reject invitation'));
  });
}

function openTeamOptions(button) {
  const teamId = button.dataset.teamId;
  const teamName = button.dataset.teamName || "";
  const isOwner = button.dataset.isOwner === 'true';
  const isAdmin = isAdminUserForTeams();
  const canManage = isOwner || isAdmin;
  const visibility = button.dataset.visibility;
  openMembersFromOptions(teamId, canManage, visibility, teamName);
}

function openMembersFromOptions(teamId, canManage, visibility = "", teamName = "") {
  closeTeamOptionsModal();

  fetch(`${window.ROOT_PATH}/teams/${teamId}/members`, {
    headers: {
      'Authorization': 'Bearer ' + (getCookie('jwt_token') || '')
    }
  })
    .then(res => res.json())
    .then(members => {
      renderTeamMembersModal(members, canManage, { teamId, visibility, teamName });
      document.getElementById('team-edit-modal').classList.remove('hidden');
    })
    .catch(err => {
      showErrorMessage(resolveTeamError(err, 'Failed to load team members'));
    });
}

function openJoinRequestsFromManage(teamId) {
  viewJoinRequestsSafe({
    getAttribute: () => teamId
  });
}

function openEditTeamModalById(teamId) {
  openEditTeamModal({ dataset: { teamId } });
}

function openJoinRequestsFromOptions(teamId) {
  // 1️⃣ Close Team Options modal
  closeTeamOptionsModal();

  // 2️⃣ Reuse existing join-requests logic
  viewJoinRequestsSafe({
    getAttribute: () => teamId
  });
}

function closeTeamOptionsModal() {
  document.getElementById('team-options-modal').classList.add('hidden');
}

function openEditTeamModal(button) {
  const teamId = button.dataset.teamId;

  fetch(`${window.ROOT_PATH}/teams/${teamId}`, {
    method: 'GET',
    headers: {
      'Authorization': 'Bearer ' + (getCookie('jwt_token') || '')
    }
  })
  .then(res => res.json())
  .then(team => {
    showEditTeamForm(team);
  })
  .catch(err => {
    showErrorMessage(resolveTeamError(err, 'Failed to load team'));
  });
}

function openMemberViewModal(teamId) {
  fetch(`${window.ROOT_PATH}/teams/${teamId}/members`, {
    headers: {
      'Authorization': 'Bearer ' + (getCookie('jwt_token') || '')
    }
  })
  .then(res => res.json())
  .then(members => {
    renderTeamMembersModal(members, false, { teamId });
    document.getElementById('team-edit-modal').classList.remove('hidden');
  })
  .catch(err => {
    showErrorMessage(resolveTeamError(err, 'Failed to load members'));
  });
}

// ===============================
// Loaders
// ===============================

function onTeamFilterClick(button, type) {
  syncAdminOtherTeamsFilterVisibility();
  // 1️⃣ reset all buttons
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.classList.remove('active', 'bg-[#2561C1]', 'text-white');
    btn.classList.add(
      'bg-white',
      'dark:bg-gray-700',
      'text-gray-700',
      'dark:text-gray-300'
    );
  });

  // 2️⃣ activate clicked button
  button.classList.add('active', 'bg-[#2561C1]', 'text-white');
  button.classList.remove(
    'bg-white',
    'dark:bg-gray-700',
    'text-gray-700',
    'dark:text-gray-300'
  );

  // 3️⃣ load data
  loadTeamsByRelationship(type);
}

function refreshTeamsPanel() {
  const activeFilterBtn = document.querySelector('.filter-btn.active');
  const activeType = activeFilterBtn?.dataset?.filter || 'all';
  loadTeamsByRelationship(activeType);
}

function loadTeamsByRelationship(type) {
  syncAdminOtherTeamsFilterVisibility();
  switch (type) {
    case 'all':
      showAllTeams();
      break;
    case 'owner':
      showOwnedTeams();
      break;
    case 'member':
      showMemberTeams();
      break;
    case 'public':
      showDiscoverTeams();
      break;
    case 'invitations':
      showInvitations();
      break;
    case 'others':
      showOtherTeams();
      break;
    default:
      showAllTeams();
  }
}

async function fetchAllTeams() {
  const res = await fetch(`${window.ROOT_PATH}/teams`, {
    credentials: 'same-origin',
    headers: {
      'Accept': 'application/json',
      'Authorization': 'Bearer ' + (getCookie('jwt_token') || '')
    }
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Failed to load teams');
  }

  return res.json();
}

async function showAllTeams() {
  const container = document.getElementById('teams-list');
  container.innerHTML = '<p class="col-span-full text-center py-8 text-gray-500 dark:text-gray-400"><span class="animate-pulse">Loading teams...</span></p>';

  try {
    const data = await fetchAllTeams();
    const normalized = normalizeTeams(data.teams);
    const { ownTeams } = splitAdminOwnVsOtherTeams(normalized);
    console.log('✅ fetched teams', data);
    renderTeamsList({
        teams: ownTeams,
        source: 'teams'
    });
  } catch (err) {
    container.innerHTML = '<p class="col-span-full text-center py-6 text-red-500">Failed to load teams</p>';
  }
}

async function showOtherTeams() {
  const container = document.getElementById('teams-list');
  container.innerHTML = '<p class="col-span-full text-center py-8 text-gray-500 dark:text-gray-400"><span class="animate-pulse">Loading teams...</span></p>';

  try {
    const data = await fetchAllTeams();
    const normalized = normalizeTeams(data.teams);
    const { otherTeams } = splitAdminOwnVsOtherTeams(normalized);
    renderTeamsList({
      teams: otherTeams,
      source: 'teams'
    });
  } catch (err) {
    console.error(err);
    container.innerHTML = '<p class="col-span-full text-center py-6 text-red-500">Failed to load teams</p>';
  }
}

async function showOwnedTeams() {
  const container = document.getElementById('teams-list');
  container.innerHTML = '<p class="col-span-full text-center py-8 text-gray-500 dark:text-gray-400"><span class="animate-pulse">Loading teams...</span></p>';

  try {
    const data = await fetchAllTeams();
    const normalized = normalizeTeams(data.teams);
    const owned = normalized.filter(t => t.is_owner);

    renderTeamsList({
    teams: owned,
    source: 'teams'
    });
  } catch {
    container.innerHTML = '<p class="col-span-full text-center py-6 text-red-500">Failed to load teams</p>';
  }
}

async function showMemberTeams() {
  const container = document.getElementById('teams-list');
  container.innerHTML = '<p class="col-span-full text-center py-8 text-gray-500 dark:text-gray-400"><span class="animate-pulse">Loading teams...</span></p>';

  try {
    // 🔥 YOU NEED THIS LINE
    const data = await fetchAllTeams();

    const normalized = normalizeTeams(data.teams);

    const membersOnly = normalized.filter(
      t => !t.is_owner && !t.is_admin
    );

    renderTeamsList({
      teams: membersOnly,
      source: 'teams'
    });

  } catch (err) {
    console.error(err);
    container.innerHTML = '<p class="col-span-full text-center py-6 text-red-500">Failed to load teams</p>';
  }
}

async function showDiscoverTeams() {
  const container = document.getElementById('teams-list');
  container.innerHTML = '<p class="col-span-full text-center py-8 text-gray-500 dark:text-gray-400"><span class="animate-pulse">Loading public teams...</span></p>';

  try {
    const token = getCookie('jwt_token') || '';
    const headers = {
      'Accept': 'application/json'
    };
    if (token) headers['Authorization'] = 'Bearer ' + token;

    const res = await fetch(`${window.ROOT_PATH}/teams/discover`, {
      credentials: 'same-origin',
      headers
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw err?.detail ? err : { detail: `Failed to load public teams (HTTP ${res.status})` };
    }

    const teamsArray = await res.json();

    // 🔒 NORMALIZATION STEP
    const normalizedTeams = teamsArray.map(team => ({
    ...team,

    // 🔑 frontend contract
    can_join: team.is_joinable !== false,
    is_owner: false,
    is_member: false,
    is_admin: false,
    requested: Boolean(team.requested)
    }));

    renderTeamsList({
    teams: normalizedTeams,
    source: 'discover'
    });

  } catch (err) {
    const message = resolveTeamError(err, 'Failed to load public teams');
    const lower = String(message || "").toLowerCase();
    const isPermissionError =
      lower.includes("403") ||
      lower.includes("forbidden") ||
      lower.includes("permission denied") ||
      lower.includes("insufficient permission") ||
      lower.includes("insufficient permissions") ||
      lower.includes("access denied") ||
      lower.includes("not authorized") ||
      lower.includes("unauthorized");

    if (isPermissionError) {
      container.innerHTML = `
        <div class="col-span-full bg-white dark:bg-gray-800 rounded-xl shadow-sm ring-1 ring-gray-200 dark:ring-gray-700 mb-2">
          <div class="px-5 py-4 border-b border-gray-100 dark:border-gray-700">
            <div class="flex items-center gap-2">
              <span class="inline-flex h-2 w-2 rounded-full bg-yellow-500"></span>
              <h3 class="text-base font-semibold text-gray-900 dark:text-gray-100">Discover Teams</h3>
            </div>
            <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">
              Insufficient permissions.
            </p>
          </div>
          <div class="p-5">
            <p class="text-sm text-gray-600 dark:text-gray-400">
              You don’t have permission to discover teams.
              Required:
              <code class="px-1 py-0.5 rounded bg-gray-100 dark:bg-gray-700">teams.discover</code>
              (or admin access).
            </p>
          </div>
        </div>
      `;
      return;
    }

    container.innerHTML = `<p class="col-span-full text-center py-6 text-red-500">${escapeHtml(message)}</p>`;
    showErrorMessage(message);
  }
}

async function showInvitations() {
  const container = document.getElementById('teams-list');
  container.innerHTML = '<p class="col-span-full text-center py-8 text-gray-500 dark:text-gray-400"><span class="animate-pulse">Loading invitations...</span></p>';

  try {
    const res = await fetch(`${window.ROOT_PATH}/teams/invitations`, {
      credentials: 'same-origin',
      headers: {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + (getCookie('jwt_token') || '')
      }
    });

    if (!res.ok) throw new Error();

    const invitations = await res.json();

    renderInvitationsList(invitations);

  } catch {
    container.innerHTML = '<p class="col-span-full text-center py-6 text-red-500">Failed to load invitations</p>';
  }
}

var inviteUserDirectory = Array.isArray(window.inviteUserDirectory)
  ? window.inviteUserDirectory
  : [];
var invitePendingEmails = window.invitePendingEmails instanceof Set
  ? window.invitePendingEmails
  : new Set();
window.inviteUserDirectory = inviteUserDirectory;
window.invitePendingEmails = invitePendingEmails;

function ensureInviteState() {
  if (!Array.isArray(inviteUserDirectory)) {
    inviteUserDirectory = Array.isArray(window.inviteUserDirectory)
      ? window.inviteUserDirectory
      : [];
  }
  if (!(invitePendingEmails instanceof Set)) {
    if (window.invitePendingEmails instanceof Set) {
      invitePendingEmails = window.invitePendingEmails;
    } else if (Array.isArray(window.invitePendingEmails)) {
      invitePendingEmails = new Set(window.invitePendingEmails);
    } else {
      invitePendingEmails = new Set();
    }
  }
  window.inviteUserDirectory = inviteUserDirectory;
  window.invitePendingEmails = invitePendingEmails;
}

function setInviteInlineStatus(message, type = "info") {
  const status = document.getElementById("invite-inline-status");
  if (!status) return;

  status.classList.remove("hidden");
  status.className = "mb-4 rounded-lg px-3 py-2 text-sm";

  if (type === "error") {
    status.classList.add("bg-red-50", "text-red-700", "border", "border-red-200", "dark:bg-red-900/20", "dark:text-red-300", "dark:border-red-800");
  } else if (type === "success") {
    status.classList.add("bg-green-50", "text-green-700", "border", "border-green-200", "dark:bg-green-900/20", "dark:text-green-300", "dark:border-green-800");
  } else {
    status.classList.add("bg-blue-50", "text-blue-700", "border", "border-blue-200", "dark:bg-blue-900/20", "dark:text-blue-300", "dark:border-blue-800");
  }

  status.textContent = message;
}

function clearInviteInlineStatus() {
  const status = document.getElementById("invite-inline-status");
  if (!status) return;
  status.textContent = "";
  status.className = "hidden mb-4 rounded-lg px-3 py-2 text-sm";
}

function updateInviteSendButtonState() {
  const select = document.getElementById("invite-user-email-select");
  const btn = document.getElementById("invite-send-btn");
  if (!select || !btn) return;
  const enabled = Boolean(select.value);
  btn.disabled = !enabled;
  btn.className = enabled
    ? "px-4 py-2 rounded-xl bg-[#2561C1] hover:bg-[#1f56ad] text-white text-sm font-semibold"
    : "px-4 py-2 rounded-xl bg-gray-300 text-gray-600 text-sm font-semibold cursor-not-allowed dark:bg-gray-700 dark:text-gray-300";
}

function applyInviteUserFilter() {
  ensureInviteState();
  const select = document.getElementById("invite-user-email-select");
  if (!select) return;

  const query = (document.getElementById("invite-user-search")?.value || "").trim().toLowerCase();

  const filtered = inviteUserDirectory.filter((user) => {
    if (!user.email) return false;
    if (invitePendingEmails.has(user.email.toLowerCase())) return false;
    if (!query) return true;
    const haystack = `${user.full_name || ""} ${user.email}`.toLowerCase();
    return haystack.includes(query);
  });

  if (!filtered.length) {
    select.innerHTML = `<option value="">No matching users</option>`;
    updateInviteSendButtonState();
    return;
  }

  select.innerHTML =
    `<option value="">Select a user...</option>` +
    filtered
      .map((user) => {
        const tags = [
          user.is_admin ? "Admin" : "",
          user.is_active === false ? "Inactive" : ""
        ].filter(Boolean);
        const suffix = tags.length ? ` (${tags.join(", ")})` : "";
        const label = `${user.full_name || user.email} - ${user.email}${suffix}`;
        return `<option value="${escapeHtml(user.email)}">${escapeHtml(label)}</option>`;
      })
      .join("");

  updateInviteSendButtonState();
}

function formatInviteDate(dateString) {
  if (!dateString) return "Unknown";
  const d = new Date(dateString);
  if (isNaN(d.getTime())) return "Unknown";
  return d.toLocaleString();
}

async function loadPendingInvitations(teamId) {
  ensureInviteState();
  const pendingEl = document.getElementById("invite-pending-list");
  if (!pendingEl) return;

  pendingEl.innerHTML = `
    <div class="space-y-2">
      <div class="h-14 rounded-xl bg-gray-100 dark:bg-gray-800 animate-pulse"></div>
      <div class="h-14 rounded-xl bg-gray-100 dark:bg-gray-800 animate-pulse"></div>
    </div>
  `;

  try {
    const res = await fetch(`${window.ROOT_PATH}/teams/${teamId}/invitations`, {
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        Authorization: "Bearer " + (getCookie("jwt_token") || "")
      }
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(resolveTeamError(err, `Failed to load invitations (HTTP ${res.status})`));
    }

    const invitations = await res.json();
    invitePendingEmails = new Set(
      (Array.isArray(invitations) ? invitations : [])
        .map((inv) => (inv?.email || "").toLowerCase())
        .filter(Boolean)
    );
    window.invitePendingEmails = invitePendingEmails;

    if (!invitations.length) {
      pendingEl.innerHTML = `
        <div class="rounded-xl border border-dashed border-gray-300 dark:border-gray-700 p-5 text-center">
          <p class="text-sm font-medium text-gray-700 dark:text-gray-200">No pending invitations</p>
          <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">Invites you send will appear here.</p>
        </div>
      `;
      applyInviteUserFilter();
      return;
    }

    pendingEl.innerHTML = invitations.map((inv) => `
      <div class="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900/40 p-3 flex items-start justify-between gap-3">
        <div class="min-w-0">
          <p class="text-sm font-semibold text-gray-900 dark:text-gray-100 truncate">${escapeHtml(inv.email || "")}</p>
          <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">Role: ${escapeHtml(inv.role || "member")} • Sent: ${escapeHtml(formatInviteDate(inv.invited_at))}</p>
          <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">Expires: ${escapeHtml(formatInviteDate(inv.expires_at))}</p>
        </div>
        <button
          class="shrink-0 px-3 py-1.5 text-xs font-semibold rounded-xl text-red-700 hover:bg-red-50 dark:text-red-300 dark:hover:bg-red-900/20 border border-red-200 dark:border-red-800"
          onclick="revokeInvitation('${teamId}', '${inv.id}')"
        >
          Revoke
        </button>
      </div>
    `).join("");

    applyInviteUserFilter();
  } catch (err) {
    pendingEl.innerHTML = `<p class="text-sm text-red-600 dark:text-red-400">${escapeHtml(resolveTeamError(err, "Failed to load invitations"))}</p>`;
  }
}

function showInviteTab(type, clickedBtn = null) {
  const modal = document.getElementById("invite-user-modal");
  const teamId = modal?.dataset?.teamId;
  const container = document.getElementById("invite-tab-content");
  const tabs = modal?.querySelectorAll('[data-invite-tab]') || [];

  if (!container || !teamId) {
    console.error("Invite modal not ready");
    return;
  }

  tabs.forEach((btn) => {
    const active = btn.getAttribute("data-invite-tab") === type;
    btn.className = active
      ? "min-w-[140px] px-4 py-2 rounded-md text-sm font-semibold bg-[#2561C1] text-white shadow-sm"
      : "min-w-[140px] px-4 py-2 rounded-md text-sm font-semibold bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600 border border-gray-200 dark:border-gray-600";
  });

  if (type === "pending") {
    container.innerHTML = `
      <div class="rounded-xl border border-gray-200 dark:border-gray-700 bg-gray-50/60 dark:bg-gray-900/30 p-4">
        <div class="flex items-center justify-between mb-3">
          <h4 class="text-sm font-bold tracking-wide text-gray-900 dark:text-gray-100">Pending Invitations</h4>
          <button
            type="button"
            onclick="loadPendingInvitations('${teamId}')"
            class="px-2.5 py-1.5 text-xs font-semibold rounded-lg text-[#2561C1] hover:bg-blue-50 dark:text-blue-300 dark:hover:bg-blue-900/20 border border-blue-200 dark:border-blue-800"
          >
            Refresh
          </button>
        </div>
        <div id="invite-pending-list" class="space-y-2"></div>
      </div>
    `;
    loadPendingInvitations(teamId);
    return;
  }

  container.innerHTML = `
    <div class="rounded-xl border border-gray-200 dark:border-gray-700 bg-gray-50/60 dark:bg-gray-900/30 p-4">
      <h4 class="text-sm font-bold tracking-wide text-gray-900 dark:text-gray-100 mb-3">Send Invite</h4>
      <form id="invite-user-form" class="space-y-4" onsubmit="submitUserInvitation(event)">
        <input type="hidden" name="team_id" value="${teamId}" />

        <div>
          <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Search User</label>
          <input
            id="invite-user-search"
            type="text"
            placeholder="Search by name or email..."
            class="block w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2 text-sm text-gray-900 dark:text-gray-200"
          />
        </div>

        <div>
          <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">User</label>
          <select
            id="invite-user-email-select"
            name="email"
            class="block w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2 text-sm text-gray-900 dark:text-gray-200"
            required
          >
            <option value="">Loading users...</option>
          </select>
          <p class="mt-2 text-xs text-gray-500 dark:text-gray-400">Existing members and already-invited users are hidden.</p>
        </div>

        <div>
          <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Role</label>
          <select name="role" class="block w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2 text-sm text-gray-900 dark:text-gray-200">
            <option value="member" selected>Member</option>
            <option value="owner">Owner</option>
          </select>
        </div>

        <div class="flex justify-end">
          <button id="invite-send-btn" type="submit" class="px-4 py-2 rounded-xl bg-gray-300 text-gray-600 text-sm font-semibold cursor-not-allowed dark:bg-gray-700 dark:text-gray-300" disabled>
            Send Invitation
          </button>
        </div>
      </form>
    </div>
  `;

  const searchInput = document.getElementById("invite-user-search");
  const emailSelect = document.getElementById("invite-user-email-select");
  if (searchInput) searchInput.addEventListener("input", applyInviteUserFilter);
  if (emailSelect) emailSelect.addEventListener("change", updateInviteSendButtonState);
  loadInviteUserDropdown(teamId);
}

async function loadInviteUserDropdown(teamId) {
  ensureInviteState();
  const select = document.getElementById("invite-user-email-select");
  if (!select) return;

  try {
    select.innerHTML = `<option value="">Loading users...</option>`;

    const [usersRes, membersRes] = await Promise.all([
      fetch(`${window.ROOT_PATH}/teams/${teamId}/invite-candidates`, {
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          Authorization: "Bearer " + (getCookie("jwt_token") || "")
        }
      }),
      fetch(`${window.ROOT_PATH}/teams/${teamId}/members`, {
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          Authorization: "Bearer " + (getCookie("jwt_token") || "")
        }
      })
    ]);

    if (!usersRes.ok) {
      const err = await usersRes.json().catch(() => ({}));
      throw new Error(resolveTeamError(err, `Failed to load users (HTTP ${usersRes.status})`));
    }
    if (!membersRes.ok) {
      const err = await membersRes.json().catch(() => ({}));
      throw new Error(resolveTeamError(err, `Failed to load members (HTTP ${membersRes.status})`));
    }

    const usersData = await usersRes.json();
    const membersData = await membersRes.json();

    const memberEmails = new Set(
      (Array.isArray(membersData) ? membersData : [])
        .map((m) => (m?.user_email || "").toLowerCase())
        .filter(Boolean)
    );

    const rawUsers = Array.isArray(usersData) ? usersData : Array.isArray(usersData.users) ? usersData.users : [];
    const userMap = new Map();

    rawUsers.forEach((u) => {
      const userObj = typeof u === "string" ? { email: u } : (u || {});
      const email = (userObj.email || "").trim();
      if (!email) return;
      if (memberEmails.has(email.toLowerCase())) return;
      userMap.set(email.toLowerCase(), {
        email,
        full_name: userObj.full_name || "",
        is_admin: Boolean(userObj.is_admin),
        is_active: typeof userObj.is_active === "boolean" ? userObj.is_active : true
      });
    });

    inviteUserDirectory = Array.from(userMap.values()).sort((a, b) =>
      (a.full_name || a.email).localeCompare(b.full_name || b.email)
    );
    window.inviteUserDirectory = inviteUserDirectory;

    if (!inviteUserDirectory.length) {
      select.innerHTML = `<option value="">No eligible users available</option>`;
      updateInviteSendButtonState();
      return;
    }

    applyInviteUserFilter();
  } catch (error) {
    select.innerHTML = `<option value="">Failed to load users</option>`;
    showErrorMessage(resolveTeamError(error, "Failed to load users"));
    setInviteInlineStatus(resolveTeamError(error, "Failed to load users"), "error");
  }
}

function showEditTeamForm(team) {
  const container = document.getElementById('team-edit-modal-content');
  const safeName = escapeHtml(team?.name || "");
  const safeDesc = escapeHtml(team?.description || "");
  const safeMax = Number(team?.max_members || 50);
  const safeTeamId = escapeHtml(team?.id || "");

  container.innerHTML = `
  <div class="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-2xl shadow-sm p-6">
    <div class="flex items-center justify-between mb-6">
      <div>
        <h3 class="text-xl font-bold text-gray-900 dark:text-gray-100">Edit Team</h3>
        <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">Update team metadata and limits.</p>
      </div>
      <button
        type="button"
        onclick="document.getElementById('team-edit-modal').classList.add('hidden')"
        class="text-gray-400 hover:text-gray-600 dark:text-gray-300 dark:hover:text-gray-100 text-lg"
      >
        ✕
      </button>
    </div>

    <form onsubmit="submitTeamUpdate(event, '${safeTeamId}')">
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div class="md:col-span-2">
          <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Team Name</label>
          <input
            name="name"
            value="${safeName}"
            class="block w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2 text-sm text-gray-900 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-[#0b1f3a] dark:focus:ring-[#f2b705]"
            required
          />
        </div>

        <div class="md:col-span-2">
          <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Description</label>
          <textarea
            name="description"
            rows="3"
            class="block w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2 text-sm text-gray-900 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-[#0b1f3a] dark:focus:ring-[#f2b705]"
          >${safeDesc}</textarea>
        </div>

        <div>
          <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Visibility</label>
          <select
            name="visibility"
            class="block w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2 text-sm text-gray-900 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-[#0b1f3a] dark:focus:ring-[#f2b705]"
          >
            <option value="public" ${team.visibility === 'public' ? 'selected' : ''}>Public</option>
            <option value="private" ${team.visibility === 'private' ? 'selected' : ''}>Private</option>
          </select>
        </div>

        <div>
          <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Maximum Members</label>
          <input
            type="number"
            name="max_members"
            value="${safeMax}"
            class="block w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2 text-sm text-gray-900 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-[#0b1f3a] dark:focus:ring-[#f2b705]"
            placeholder="Max Members"
          />
        </div>
      </div>

      <div class="mt-6 flex justify-end gap-3">
        <button
          type="button"
          onclick="document.getElementById('team-edit-modal').classList.add('hidden')"
          class="px-4 py-2 rounded-xl border border-gray-300 dark:border-gray-700 text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-900 hover:bg-gray-50 dark:hover:bg-gray-800 text-sm font-semibold"
        >
          Cancel
        </button>
        <button
          type="submit"
          class="px-4 py-2 rounded-xl bg-[#2561C1] hover:bg-[#1f56ad] text-white text-sm font-semibold"
        >
          Save Changes
        </button>
      </div>
    </form>
  </div>
  `;

  document.getElementById('team-edit-modal').classList.remove('hidden');
}

// ===============================
// Team Actions
// ===============================
// Safe team action functions using data attributes
function requestToJoinTeamSafe(button) {
    const teamId = button.getAttribute('data-team-id');
    const teamName = button.getAttribute('data-team-name');

    if (!confirm(`Request to join "${teamName}"?`)) return;

    fetch(`${window.ROOT_PATH}/teams/${teamId}/join`, {
    method: 'POST',
    headers: {
        'Authorization': 'Bearer ' + (getCookie('jwt_token') || ''),
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        message: null
    })
    })
    .then(response => {
    if (!response.ok) {
        return response.json().then(err => { throw err; });
    }
    return response.json();
    })
    .then(data => {
    showSuccessMessage(data?.message || 'Join request sent successfully');
    button.disabled = true;
    button.innerText = 'Request Pending';
    })
    .catch(error => {
    console.error('Join request failed:', error);
    showErrorMessage(resolveTeamError(error, 'Failed to send join request'));
    });
}

function leaveTeamSafe(button) {
    const teamId = button.getAttribute('data-team-id');
    const teamName = button.getAttribute('data-team-name');

    if (!confirm(`Leave team "${teamName}"? You will lose access to team resources.`)) {
    return;
    }

    fetch(`${window.ROOT_PATH}/teams/${teamId}/leave`, {
    method: 'DELETE',
    headers: {
        'Authorization': 'Bearer ' + (getCookie('jwt_token') || '')
    }
    })
    .then(response => {
    if (!response.ok) {
        return response.json().then(err => { throw err; });
    }
    return response.json();
    })
    .then(data => {
    showSuccessMessage(data?.message || 'Successfully left the team');

    // Refresh teams list
    loadTeamsByRelationship('all');
    })
    .catch(error => {
    console.error('Error leaving team:', error);
    showErrorMessage(resolveTeamError(error, 'Failed to leave team'));
    });
}

function openJoinConfirm(button) {
  const modal = document.getElementById('join-confirm-modal');

  // store data on the modal itself (same pattern as others)
  modal.dataset.teamId = button.dataset.teamId;
  modal.dataset.buttonRefId = button.dataset.teamId; // optional

  document.getElementById('join-confirm-team-name').textContent =
    `"${button.dataset.teamName}"`;

  const errEl = document.getElementById('join-confirm-error');
  if (errEl) {
    errEl.textContent = '';
    errEl.classList.add('hidden');
  }

  const confirmBtn = document.getElementById('confirm-join-btn');
  if (confirmBtn) {
    confirmBtn.disabled = false;
    confirmBtn.textContent = 'Request To Join';
    confirmBtn.className = 'px-4 py-2 rounded-xl text-sm font-semibold bg-[#2561C1] hover:bg-[#1f56ad] text-white';
  }

  modal.classList.remove('hidden');
}

function closeJoinConfirm() {
  document.getElementById('join-confirm-modal').classList.add('hidden');
  const errEl = document.getElementById('join-confirm-error');
  if (errEl) {
    errEl.textContent = '';
    errEl.classList.add('hidden');
  }
  pendingJoinTeamId = null;
  pendingJoinButton = null;
}

async function confirmJoinRequest() {
  const modal = document.getElementById('join-confirm-modal');
  const teamId = modal.dataset.teamId;
  const confirmBtn = document.getElementById('confirm-join-btn');
  const errEl = document.getElementById('join-confirm-error');

  if (!teamId) return;

  if (errEl) {
    errEl.textContent = '';
    errEl.classList.add('hidden');
  }

  if (confirmBtn) {
    confirmBtn.disabled = true;
    confirmBtn.textContent = 'Sending...';
    confirmBtn.className = 'px-4 py-2 rounded-xl text-sm font-semibold bg-gray-300 text-gray-600 cursor-not-allowed dark:bg-gray-700 dark:text-gray-300';
  }

  try {
    const res = await fetch(
    `${window.ROOT_PATH}/teams/${teamId}/join`,
    {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + (getCookie('jwt_token') || ''),
        'Content-Type': 'application/json'
        },
        body: JSON.stringify({
        message: null   // ✅ backend expects this
        })
    }
    );

    const data = await res.json();

    if (!res.ok) {
      const msg = resolveTeamError(data, 'Failed to send join request');
      if (errEl) {
        errEl.textContent = msg;
        errEl.classList.remove('hidden');
      }
      showErrorMessage(msg);
      return;
    }

    // ✅ Close modal
    modal.classList.add('hidden');

    // ✅ Refresh Discover list (same behavior as others)
    showDiscoverTeams();

    showSuccessMessage(data?.message || 'Join request sent successfully');

  } catch (err) {
    const msg = resolveTeamError(err, 'Unexpected error');
    if (errEl) {
      errEl.textContent = msg;
      errEl.classList.remove('hidden');
    }
    showErrorMessage(msg);
  } finally {
    if (confirmBtn) {
      confirmBtn.disabled = false;
      confirmBtn.textContent = 'Request To Join';
      confirmBtn.className = 'px-4 py-2 rounded-xl text-sm font-semibold bg-[#2561C1] hover:bg-[#1f56ad] text-white';
    }
  }
}

function submitTeamUpdate(event, teamId) {
    event.preventDefault();

    const form = event.target;
    const formData = new FormData(form);

    fetch(`${window.ROOT_PATH}/teams/${teamId}`, {
    method: 'PUT',
    headers: {
        'Authorization': 'Bearer ' + (getCookie('jwt_token') || ''),
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        name: formData.get('name'),
        description: formData.get('description'),
        visibility: formData.get('visibility'),
        max_members: Number(formData.get('max_members'))
    })
    })
    .then(response => {
    if (!response.ok) {
        return response.json().then(err => { throw err; });
    }
    return response.json();
    })
    .then(data => {
    showSuccessMessage(data?.message || 'Team updated successfully');
    document.getElementById('team-edit-modal').classList.add('hidden');

    // Refresh teams list
    loadTeamsByRelationship('all');
    })
    .catch(error => {
    console.error('Error updating team:', error);
    showErrorMessage(resolveTeamError(error, 'Failed to update team'));
    });
}

function manageTeamMembersSafe(button) {
  const teamId = button.getAttribute('data-team-id');
  const isOwner = button.getAttribute('data-is-owner') === 'true';

  // Close Team Options first (important)
  const optionsModal = document.getElementById('team-options-modal');
  if (optionsModal) optionsModal.classList.add('hidden');

  fetch(`${window.ROOT_PATH}/teams/${teamId}/members`, {
    headers: {
      'Authorization': 'Bearer ' + (getCookie('jwt_token') || '')
    }
  })
    .then(res => {
      if (!res.ok) {
        return res.json().then(err => { throw err; });
      }
      return res.json();
    })
    .then(members => {
      renderTeamMembersModal(members, isOwner);
      document.getElementById('team-edit-modal').classList.remove('hidden');
    })
    .catch(err => {
      showErrorMessage(resolveTeamError(err, 'Failed to load team members'));
    });
}

function deleteTeamSafe(button) {
  const teamId = button.getAttribute('data-team-id');
  const teamName = button.getAttribute('data-team-name');

  if (!confirm(`Delete team "${teamName}"? This action cannot be undone.`)) {
    return;
  }

  fetch(`${window.ROOT_PATH}/teams/${teamId}`, {
    method: 'DELETE',
    headers: {
      'Authorization': 'Bearer ' + (getCookie('jwt_token') || '')
    }
  })
  .then(response => {
    if (!response.ok) {
      return response.json().then(err => { throw err; });
    }
    return response.json();
  })
  .then(data => {
    showSuccessMessage(data?.message || 'Team deleted successfully');
    loadTeamsByRelationship('all'); // Refresh the teams list (JSON → HTML)
  })
  .catch(error => {
    console.error('Error deleting team:', error);
    showErrorMessage(resolveTeamError(error, 'Failed to delete team'));
  });
}

function cancelJoinRequest(teamId, requestId) {
    if (confirm('Cancel your join request?')) {
    htmx.ajax('DELETE', window.ROOT_PATH + '/teams/' + teamId + '/join-request/' + requestId, {
        target: '#unified-teams-list',
        swap: 'innerHTML'
    }).then(() => {
        loadTeamsByRelationship('all'); // Refresh the full list
    });
    }
}

function viewJoinRequestsSafe(button) {
  const teamId = button.getAttribute('data-team-id');

  fetch(`${window.ROOT_PATH}/teams/${teamId}/join-requests`, {
    headers: {
      'Authorization': 'Bearer ' + (getCookie('jwt_token') || '')
    }
  })
  .then(response => {
    if (!response.ok) {
      return response.json().then(err => { throw err; });
    }
    return response.json();
  })
  .then(requests => {
    renderJoinRequestsModal(requests);
    document
      .getElementById('team-join-requests-modal')
      .classList.remove('hidden');
  })
  .catch(error => {
    console.error('Error loading join requests:', error);
    showErrorMessage(resolveTeamError(error, 'Failed to load join requests'));
  });
}

function rejectJoinRequestSafe(button) {
  const teamId = button.dataset.teamId;
  const requestId = button.dataset.requestId;

  if (!confirm('Reject this join request?')) return;

  fetch(`${window.ROOT_PATH}/teams/${teamId}/join-requests/${requestId}`, {
    method: 'DELETE',
    headers: {
      'Authorization': 'Bearer ' + (getCookie('jwt_token') || '')
    }
  })
  .then(res => {
    if (!res.ok) return res.json().then(err => { throw err; });
    return res.json();
  })
  .then(() => {
    showSuccessMessage('Join request rejected');
    openJoinRequestsFromOptions(teamId); // reload modal content
    loadTeamsByRelationship('all');
  })
  .catch(err => showErrorMessage(resolveTeamError(err, 'Failed to reject request')));
}

function approveJoinRequestSafe(button) {
  const teamId = button.dataset.teamId;
  const requestId = button.dataset.requestId;

  if (!confirm('Approve this join request?')) return;

  fetch(`${window.ROOT_PATH}/teams/${teamId}/join-requests/${requestId}/approve`, {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + (getCookie('jwt_token') || '')
    }
  })
  .then(res => {
    if (!res.ok) return res.json().then(err => { throw err; });
    return res.json();
  })
  .then(() => {
    showSuccessMessage('Join request approved');
    loadTeamsByRelationship('all');
    document.getElementById('team-join-requests-modal').classList.add('hidden');
  })
  .catch(err => showErrorMessage(resolveTeamError(err, 'Failed to approve request')));
}

function submitUserInvitation(event) {
  event.preventDefault();

  const form = event.target;
  const formData = new FormData(form);
  const sendBtn = document.getElementById("invite-send-btn");

  const teamId = formData.get('team_id');
  const email = formData.get('email');
  const role = formData.get('role');

  if (!teamId || !email || !role) {
    showErrorMessage('Please fill all required fields');
    setInviteInlineStatus('Please fill all required fields', 'error');
    return;
  }

  if (sendBtn) {
    sendBtn.disabled = true;
    sendBtn.textContent = 'Sending...';
    sendBtn.className = 'px-4 py-2 rounded-xl bg-gray-300 text-gray-600 text-sm font-semibold cursor-not-allowed dark:bg-gray-700 dark:text-gray-300';
  }

  fetch(`${window.ROOT_PATH}/teams/${teamId}/invitations`, {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + (getCookie('jwt_token') || ''),
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      email,
      role
    })
  })
    .then(res => {
      if (!res.ok) {
        return res.json().then(err => { throw err; });
      }
      return res.json();
    })
    .then(() => {
      showSuccessMessage('Invitation sent successfully');
      setInviteInlineStatus('Invitation sent successfully', 'success');
      form.reset();
      const searchInput = document.getElementById('invite-user-search');
      if (searchInput) searchInput.value = '';
      loadPendingInvitations(teamId);
      loadInviteUserDropdown(teamId);
    })
    .catch(err => {
      console.error('Invite failed:', err);
      showErrorMessage(resolveTeamError(err, 'Failed to send invitation'));
      setInviteInlineStatus(resolveTeamError(err, 'Failed to send invitation'), 'error');
    })
    .finally(() => {
      if (sendBtn) {
        sendBtn.textContent = 'Send Invitation';
      }
      updateInviteSendButtonState();
    });
}

function changeMemberRole(selectEl) {
  const userEmail = selectEl.dataset.userEmail;
  const teamId = selectEl.dataset.teamId;
  const newRole = selectEl.value;
  const currentRole = selectEl.dataset.currentRole;

  if (!confirm(`Change role of ${userEmail} from ${currentRole} to ${newRole}?`)) {
    // revert selection if cancelled
    selectEl.value = currentRole;
    return;
  }

  fetch(`${window.ROOT_PATH}/teams/${teamId}/members/${userEmail}`, {
    method: 'PUT',
    headers: {
      'Authorization': 'Bearer ' + (getCookie('jwt_token') || ''),
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      role: newRole
    })
  })
  .then(res => {
    if (!res.ok) {
      return res.json().then(err => { throw err; });
    }
    return res.json().catch(() => ({}));
  })
  .then(data => {
    showSuccessMessage(data?.message || 'Role updated successfully');

    // update stored current role
    selectEl.dataset.currentRole = newRole;

    // optional: refresh members list
    openMembersFromOptions(teamId, true);
  })
  .catch(err => {
    showErrorMessage(resolveTeamError(err, 'Failed to update role'));

    // revert role visually
    selectEl.value = currentRole;
  });
}

function removeTeamMember(button) {
  const userEmail = button.dataset.userEmail;
  const teamId = button.dataset.teamId;

  if (!confirm(`Remove ${userEmail} from this team?`)) return;

  fetch(`${window.ROOT_PATH}/teams/${teamId}/members/${userEmail}`, {
    method: 'DELETE',
    headers: {
      'Authorization': 'Bearer ' + (getCookie('jwt_token') || '')
    }
  })
  .then(res => {
    if (!res.ok) {
      return res.json().then(err => { throw err; });
    }
    return res.json().catch(() => ({}));
  })
  .then(() => {
    showSuccessMessage('Member removed successfully');

    // Refresh members modal
    openMembersFromOptions(teamId, true);

    // Refresh teams list
    loadTeamsByRelationship('all');
  })
  .catch(err => {
    showErrorMessage(resolveTeamError(err, 'Failed to remove member'));
  });
}

function openInviteUserModal(teamId) {
  const modal = document.getElementById('invite-user-modal');
  modal.dataset.teamId = teamId;
  modal.classList.remove('hidden');
  showInviteTab('send');
}

function closeInviteUserModal() {
  document.getElementById('invite-user-modal').classList.add('hidden');
  ensureInviteState();
  inviteUserDirectory = [];
  invitePendingEmails = new Set();
  window.inviteUserDirectory = inviteUserDirectory;
  window.invitePendingEmails = invitePendingEmails;
  clearInviteInlineStatus();
}

window.filterTeams = filterTeams;

function revokeInvitation(teamId, invitationId) {
  if (!confirm("Revoke this invitation?")) return;

  fetch(`${window.ROOT_PATH}/teams/${teamId}/invitations/${invitationId}`, {
    method: 'DELETE',
    headers: {
      'Authorization': 'Bearer ' + (getCookie('jwt_token') || '')
    }
  })
  .then(res => {
    if (!res.ok) {
      return res.json().then(err => { throw err; });
    }
    return res.json();
  })
  .then(data => {
    showSuccessMessage(data?.message || 'Invitation revoked successfully');
    setInviteInlineStatus(data?.message || 'Invitation revoked successfully', 'success');
    loadPendingInvitations(teamId);
    loadInviteUserDropdown(teamId);
  })
  .catch(err => {
    showErrorMessage(resolveTeamError(err, 'Failed to revoke invitation'));
    setInviteInlineStatus(resolveTeamError(err, 'Failed to revoke invitation'), 'error');
  });
}


/* ---------------------------------------------------------------------------
  Robust reloadAllResourceSections
  - Replaces each section's full innerHTML with a server-rendered partial
  - Restores saved initial markup on failure
  - Re-runs initializers (Alpine, CodeMirror, select/pills, event handlers)
--------------------------------------------------------------------------- */

(function registerReloadAllResourceSections() {
    // list of sections we manage
    const SECTION_NAMES = [
        "tools",
        "resources",
        "prompts",
        "servers",
        "gateways",
        "catalog",
    ];

    // Save initial markup on first full load so we can restore exactly if needed
    document.addEventListener("DOMContentLoaded", () => {
        window.__initialSectionMarkup = window.__initialSectionMarkup || {};
        SECTION_NAMES.forEach((s) => {
            const el = document.getElementById(`${s}-section`);
            if (el && !(s in window.__initialSectionMarkup)) {
                // store the exact innerHTML produced by the server initially
                window.__initialSectionMarkup[s] = el.innerHTML;
            }
        });
    });

    // Helper: try to re-run common initializers after a section's DOM is replaced
    function reinitializeSection(sectionEl, sectionName) {
        try {
            if (!sectionEl) {
                return;
            }

            // 1) Re-init Alpine for the new subtree (if Alpine is present)
            try {
                if (window.Alpine) {
                    // For Alpine 3 use initTree if available
                    if (typeof window.Alpine.initTree === "function") {
                        window.Alpine.initTree(sectionEl);
                    } else if (
                        typeof window.Alpine.discoverAndRegisterComponents ===
                        "function"
                    ) {
                        // fallback: attempt a component discovery if available
                        window.Alpine.discoverAndRegisterComponents(sectionEl);
                    }
                }
            } catch (err) {
                console.warn(
                    "Alpine re-init failed for section",
                    sectionName,
                    err,
                );
            }

            // 2) Re-initialize tool/resource/pill helpers that expect DOM structure
            try {
                // these functions exist elsewhere in admin.js; call them if present
                if (typeof initResourceSelect === "function") {
                    // Many panels use specific ids — attempt to call generic initializers if they exist
                    initResourceSelect(
                        "associatedResources",
                        "resource-pills",
                        "resource-warn",
                        10,
                        null,
                        null,
                    );
                }
                if (typeof initToolSelect === "function") {
                    initToolSelect(
                        "associatedTools",
                        "tool-pills",
                        "tool-warn",
                        10,
                        null,
                        null,
                    );
                }
                // restore generic tool/resource selection areas if present
                if (typeof initResourceSelect === "function") {
                    // try specific common containers if present (safeGetElement suppresses warnings)
                    const containers = [
                        "edit-server-resources",
                        "edit-server-tools",
                    ];
                    containers.forEach((cid) => {
                        const c = document.getElementById(cid);
                        if (c && typeof initResourceSelect === "function") {
                            // caller may have different arg signature — best-effort call is OK
                            // we don't want to throw here if arguments mismatch
                            try {
                                /* no args: assume function will find DOM by ids */ initResourceSelect();
                            } catch (e) {
                                /* ignore */
                            }
                        }
                    });
                }
            } catch (err) {
                console.warn("Select/pill reinit error", err);
            }

            // 3) Re-run integration & schema handlers which attach behaviour to new inputs
            try {
                if (typeof setupIntegrationTypeHandlers === "function") {
                    setupIntegrationTypeHandlers();
                }
                if (typeof setupSchemaModeHandlers === "function") {
                    setupSchemaModeHandlers();
                }
            } catch (err) {
                console.warn("Integration/schema handler reinit failed", err);
            }

            // 4) Reinitialize CodeMirror editors within the replaced DOM (if CodeMirror used)
            try {
                if (window.CodeMirror) {
                    // For any <textarea class="codemirror"> re-create or refresh editors
                    const textareas = sectionEl.querySelectorAll("textarea");
                    textareas.forEach((ta) => {
                        // If the page previously attached a CodeMirror instance on same textarea,
                        // the existing instance may have been stored on the element. If refresh available, refresh it.
                        if (
                            ta.CodeMirror &&
                            typeof ta.CodeMirror.refresh === "function"
                        ) {
                            ta.CodeMirror.refresh();
                        } else {
                            // Create a new CodeMirror instance only when an explicit init function is present on page
                            if (
                                typeof window.createCodeMirrorForTextarea ===
                                "function"
                            ) {
                                try {
                                    window.createCodeMirrorForTextarea(ta);
                                } catch (e) {
                                    // ignore - not all textareas need CodeMirror
                                }
                            }
                        }
                    });
                }
            } catch (err) {
                console.warn("CodeMirror reinit failed", err);
            }

            // 5) Re-attach generic event wiring that is expected by the UI (checkboxes, buttons)
            try {
                // checkbox-driven pill updates
                const checkboxChangeEvent = new Event("change", {
                    bubbles: true,
                });
                sectionEl
                    .querySelectorAll('input[type="checkbox"]')
                    .forEach((cb) => {
                        // If there were checkbox-specific change functions on page, they will now re-run
                        cb.dispatchEvent(checkboxChangeEvent);
                    });

                // Reconnect any HTMX triggers that expect a load event
                if (window.htmx && typeof window.htmx.trigger === "function") {
                    // find elements with data-htmx or that previously had an HTMX load
                    const htmxTargets = sectionEl.querySelectorAll(
                        "[hx-get], [hx-post], [data-hx-load]",
                    );
                    htmxTargets.forEach((el) => {
                        try {
                            window.htmx.trigger(el, "load");
                        } catch (e) {
                            /* ignore */
                        }
                    });
                }
            } catch (err) {
                console.warn("Event wiring re-attach failed", err);
            }

            // 6) Accessibility / visual: force a small layout reflow, useful in some browsers
            try {
                // eslint-disable-next-line no-unused-expressions
                sectionEl.offsetHeight; // read to force reflow
            } catch (e) {
                /* ignore */
            }
        } catch (err) {
            console.error("Error reinitializing section", sectionName, err);
        }
    }

    function updateSectionHeaders(teamId) {
        const sections = [
            "tools",
            "resources",
            "prompts",
            "servers",
            "gateways",
        ];

        sections.forEach((section) => {
            const header = document.querySelector(
                "#" + section + "-section h2",
            );
            if (header) {
                // Remove existing team badge
                const existingBadge = header.querySelector(".team-badge");
                if (existingBadge) {
                    existingBadge.remove();
                }

                // Add team badge if team is selected
                if (teamId && teamId !== "") {
                    const teamName = getTeamNameById(teamId);
                    if (teamName) {
                        const badge = document.createElement("span");
                        badge.className =
                            "team-badge inline-flex items-center px-2 py-1 ml-2 text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200 rounded-full";
                        badge.textContent = teamName;
                        header.appendChild(badge);
                    }
                }
            }
        });
    }

    function getTeamNameById(teamId) {
        // Get team name from Alpine.js data or fallback
        const teamSelector = document.querySelector('[x-data*="selectedTeam"]');
        if (
            teamSelector &&
            teamSelector._x_dataStack &&
            teamSelector._x_dataStack[0].teams
        ) {
            const team = teamSelector._x_dataStack[0].teams.find(
                (t) => t.id === teamId,
            );
            return team ? team.name : null;
        }
        return null;
    }

    // The exported function: reloadAllResourceSections
    async function reloadAllResourceSections(teamId) {
        const sections = [
            "tools",
            "resources",
            "prompts",
            "servers",
            "gateways",
        ];

        // ensure there is a ROOT_PATH set
        if (!window.ROOT_PATH) {
            console.warn(
                "ROOT_PATH not defined; aborting reloadAllResourceSections",
            );
            return;
        }

        // Iterate sections sequentially to avoid overloading the server and to ensure consistent order.
        for (const section of sections) {
            const sectionEl = document.getElementById(`${section}-section`);
            if (!sectionEl) {
                console.warn(`Section element not found: ${section}-section`);
                continue;
            }

            // Build server partial URL (server should return the *full HTML fragment* for the section)
            // Server endpoint pattern: /admin/sections/{section}?partial=true
            let url = `${window.ROOT_PATH}/admin/sections/${section}?partial=true`;
            if (teamId && teamId !== "") {
                url += `&team_id=${encodeURIComponent(teamId)}`;
            }

            try {
                const resp = await fetchWithTimeout(
                    url,
                    { credentials: "same-origin" },
                    window.MCPGATEWAY_UI_TOOL_TEST_TIMEOUT || 60000,
                );
                if (!resp.ok) {
                    throw new Error(`HTTP ${resp.status}`);
                }
                const html = await resp.text();

                // Replace entire section's innerHTML with server-provided HTML to keep DOM identical.
                // Use safeSetInnerHTML with isTrusted = true because this is server-rendered trusted content.
                safeSetInnerHTML(sectionEl, html, true);

                // After replacement, re-run local initializers so the new DOM behaves like initial load
                reinitializeSection(sectionEl, section);
            } catch (err) {
                console.error(
                    `Failed to load section ${section} from server:`,
                    err,
                );

                // Restore the original markup exactly as it was on initial load (fallback)
                if (
                    window.__initialSectionMarkup &&
                    window.__initialSectionMarkup[section]
                ) {
                    sectionEl.innerHTML =
                        window.__initialSectionMarkup[section];
                    // Re-run initializers on restored markup as well
                    reinitializeSection(sectionEl, section);
                    console.log(
                        `Restored initial markup for section ${section}`,
                    );
                } else {
                    // No fallback available: leave existing DOM intact and show error to console
                    console.warn(
                        `No saved initial markup for section ${section}; leaving DOM untouched`,
                    );
                }
            }
        }

        // Update headers (team badges) after reload
        try {
            if (typeof updateSectionHeaders === "function") {
                updateSectionHeaders(teamId);
            }
        } catch (err) {
            console.warn("updateSectionHeaders failed after reload", err);
        }

        console.log("✓ reloadAllResourceSections completed");
    }

    // Export to global to keep old callers working
    window.reloadAllResourceSections = reloadAllResourceSections;
})();

// Expose selective import functions to global scope
window.previewImport = previewImport;
window.handleSelectiveImport = handleSelectiveImport;
window.displayImportPreview = displayImportPreview;
window.collectUserSelections = collectUserSelections;
window.updateSelectionCount = updateSelectionCount;
window.selectAllItems = selectAllItems;
window.selectNoneItems = selectNoneItems;
window.selectOnlyCustom = selectOnlyCustom;
window.resetImportSelection = resetImportSelection;

/******************************************************
 * RBAC Module (Tokens-style: functions + window exports)
 ******************************************************/

// lightweight state
window.__rbacState = window.__rbacState || {
    initialized: false,
    myPermissions: [],
    canUserManage: false, // admin.user_management
    canAudit: false,      // admin.security_audit
    rolesCache: [],
    allPermissionsCache: null,
};
window.__rbacActiveSubTab = window.__rbacActiveSubTab || "rbac-roles";

// If you already have safeJson elsewhere, keep yours.
// This is only a fallback.
if (typeof safeJson !== "function") {
    async function safeJson(resp) {
        try {
            const ct = (resp.headers && resp.headers.get("content-type")) || "";
            if (ct.includes("application/json")) return await resp.json();
            const txt = await resp.text();
            if (!txt || !txt.trim()) return null;
            if (txt.trim().startsWith("{") || txt.trim().startsWith("[")) return JSON.parse(txt);
            return { detail: txt };
        } catch (_e) {
            return null;
        }
    }
}


function shortId(id) {
  if (!id) return "";
  const s = String(id);
  return s.length > 10 ? `${s.slice(0, 8)}…` : s;
}

function formatIsoDate(iso) {
  if (!iso) return "Never";
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    // Example: 24 Dec 2026, 15:29
    return d.toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch (_e) {
    return iso;
  }
}


async function rbacHeaders() {
    return {
        Authorization: `Bearer ${await getAuthToken()}`,
        "Content-Type": "application/json",
    };
}

function renderRbacAccessRestricted(containerIdOrEl, requiredPerm) {
    const el = typeof containerIdOrEl === "string" ? safeGetElement(containerIdOrEl) : containerIdOrEl;
    if (!el) return;
    el.innerHTML = `
      <div class="border border-yellow-200 bg-yellow-50 text-yellow-900 dark:border-yellow-900/40 dark:bg-yellow-900/20 dark:text-yellow-100 rounded-lg p-4">
        <div class="font-semibold mb-1">Access restricted</div>
        <div class="text-sm opacity-90">
          You don’t have permission to view this section${requiredPerm ? ` (required: <code>${escapeHtml(requiredPerm)}</code>)` : ""}.
        </div>
        <div class="mt-3">
          <button type="button"
            class="px-3 py-2 rounded-md bg-white text-gray-800 hover:bg-gray-100 border border-yellow-200 dark:bg-gray-800 dark:text-gray-100 dark:border-yellow-900/50 dark:hover:bg-gray-700"
            onclick="showRBACSubTab('rbac-my-access')">
            View My Access
          </button>
        </div>
      </div>
    `;
}

function renderRbacInlineError(containerIdOrEl, message) {
    const el = typeof containerIdOrEl === "string" ? safeGetElement(containerIdOrEl) : containerIdOrEl;
    if (!el) return;
    el.innerHTML = `
      <div class="border border-red-200 bg-red-50 text-red-800 dark:border-red-900/40 dark:bg-red-900/20 dark:text-red-100 rounded-lg p-4">
        <div class="font-semibold mb-1">Error</div>
        <div class="text-sm">${escapeHtml(message || "Something went wrong.")}</div>
      </div>
    `;
}

function applyRBACVisibility() {
    const canManage = window.__rbacState.canUserManage;
    const canAudit = window.__rbacState.canAudit;

    const btnRoles = document.querySelector('[data-rbac-subtab="rbac-roles"]');
    const btnUserRoles = document.querySelector('[data-rbac-subtab="rbac-user-roles"]');
    const btnAudit = document.querySelector('[data-rbac-subtab="rbac-audit"]');
    const btnMy = document.querySelector('[data-rbac-subtab="rbac-my-access"]');

    if (btnRoles) btnRoles.style.display = canManage ? "" : "none";
    if (btnUserRoles) btnUserRoles.style.display = canManage ? "" : "none";
    if (btnAudit) btnAudit.style.display = canAudit ? "" : "none";
    if (btnMy) btnMy.style.display = "";

    const createBtn = safeGetElement("rbac-create-role-btn");
    if (createBtn) createBtn.style.display = canManage ? "" : "none";
}

function showRBACSubTab(subtabId) {
    window.__rbacActiveSubTab = subtabId;

    document.querySelectorAll(".rbac-subtab").forEach((el) => el.classList.add("hidden"));
    const active = safeGetElement(subtabId);
    if (active) active.classList.remove("hidden");

    document.querySelectorAll(".rbac-subtab-btn").forEach((btn) => {
        const isActive = btn.getAttribute("data-rbac-subtab") === subtabId;
        if (isActive) {
            btn.classList.remove(
                "bg-gray-100","text-gray-700","hover:bg-gray-200",
                "dark:bg-gray-700","dark:text-gray-200","dark:hover:bg-gray-600"
            );
            btn.classList.add("bg-indigo-50","text-indigo-700","dark:bg-indigo-900/30","dark:text-indigo-300");
        } else {
            btn.classList.remove("bg-indigo-50","text-indigo-700","dark:bg-indigo-900/30","dark:text-indigo-300");
            btn.classList.add(
                "bg-gray-100","text-gray-700","hover:bg-gray-200",
                "dark:bg-gray-700","dark:text-gray-200","dark:hover:bg-gray-600"
            );
        }
    });

    // lazy load per subtab
    if (subtabId === "rbac-roles") {
        loadRBACRoles();
    } else if (subtabId === "rbac-user-roles") {
        loadRBACRoleDropdown();
    } else if (subtabId === "rbac-audit") {
        initializePermissionsPanel();
    } else if (subtabId === "rbac-my-access") {
        loadRBACMyAccess();
    }
}

async function initializeRBACPanel(force = false) {
    const msg = safeGetElement("rbac-messages");
    if (msg) msg.innerHTML = "";

    if (window.__rbacState.initialized && !force) {
        showRBACSubTab(window.__rbacActiveSubTab || "rbac-roles");
        return;
    }

    window.__rbacState.initialized = true;

    await loadRBACMyPermissionsBootstrap();
    applyRBACVisibility();

        // Default open Audit subtab
    showRBACSubTab("rbac-audit");
    loadRbacUsersDropdown("rbac-assign-user-email");
    loadRbacRolesDropdown("rbac-assign-role-id");


    // Load dropdowns and permissions list
    initializePermissionsPanel(true);
    // default tab
    if (window.__rbacState.canUserManage) showRBACSubTab("rbac-roles");
    else showRBACSubTab("rbac-my-access");


}




async function loadRBACMyPermissionsBootstrap() {
    const headers = await rbacHeaders();
    const resp = await fetchWithTimeout(`${window.ROOT_PATH}/rbac/my/permissions`, { headers });

    if (resp.status === 401) throw new Error("Session expired. Please login again.");
    if (!resp.ok) {
        const err = await safeJson(resp);
        throw new Error(err?.detail || `Failed to load my permissions: HTTP ${resp.status}`);
    }

    const perms = await resp.json();
    window.__rbacState.myPermissions = perms || [];
    window.__rbacState.canUserManage = window.__rbacState.myPermissions.includes("admin.user_management");
    window.__rbacState.canAudit = window.__rbacState.myPermissions.includes("admin.security_audit");
}
async function createRole() {
    const nameEl = safeGetElement("rbac-role-name");
    const descEl = safeGetElement("rbac-role-description");
    const scopeEl = safeGetElement("rbac-role-scope");
    const statusEl = safeGetElement("rbac-create-role-status");

    if (!nameEl || !scopeEl || !statusEl) return;

    const name = nameEl.value.trim();
    const description = descEl?.value.trim() || "";
    const scope = scopeEl.value;

    // Collect permissions
    const permissions = Array.from(
        document.querySelectorAll(".rbac-role-permission:checked")
    ).map(cb => cb.value);

    // ---- Validation ----
    if (!name) {
        return showInlineStatus(statusEl, "Role name is required.", "error");
    }

    if (!permissions.length) {
        return showInlineStatus(
            statusEl,
            "Select at least one permission.",
            "error"
        );
    }

    try {
        showInlineStatus(statusEl, "Creating role…", "loading");

        const payload = {
            name,
            description,
            scope,
            permissions,
            inherits_from: null,
            is_system_role: false,
        };

        const headers = {
            ...(await rbacHeaders()),
            "Content-Type": "application/json",
        };

        const resp = await fetchWithTimeout(
            `${window.ROOT_PATH}/rbac/roles`,
            {
                method: "POST",
                headers,
                body: JSON.stringify(payload),
            }
        );

        if (!resp.ok) {
            const err = await safeJson(resp);
            let message;

            if (Array.isArray(err?.detail)) {
                message = err.detail.map(d => d.msg).join("; ");
            } else {
                message = err?.detail || `Failed: HTTP ${resp.status}`;
            }

            throw new Error(message);
        }

        showInlineStatus(
            statusEl,
            "✅ Role created successfully.",
            "success"
        );

        // Reset form
        nameEl.value = "";
        if (descEl) descEl.value = "";
        document
            .querySelectorAll(".rbac-role-permission")
            .forEach(cb => (cb.checked = false));

        // Refresh roles list
        if (typeof loadRBACRoles === "function") {
            await loadRBACRoles();
        }

        // Close modal after short delay
        setTimeout(() => {
            closeCreateRoleModal();
        }, 600);
    } catch (e) {
        console.error("createRole failed:", e);
        showInlineStatus(
            statusEl,
            e.message || "Failed to create role",
            "error"
        );
    }
}



/** Roles list **/
async function loadRBACRoles() {
    const container = safeGetElement("rbac-roles-container");
    const countEl = safeGetElement("rbac-roles-count");

    if (!container) return;

    if (!window.__rbacState.canUserManage) {
        renderRbacAccessRestricted(container, "admin.user_management");
        if (countEl) countEl.textContent = "0";
        return;
    }

    try {
        container.innerHTML =
            `<p class="text-gray-500 dark:text-gray-400">Loading roles...</p>`;
        if (countEl) countEl.textContent = "…";

        const scope = safeGetElement("rbac-roles-scope")?.value || "";
        const activeOnly =
            safeGetElement("rbac-roles-active-only")?.checked ?? true;

        const params = new URLSearchParams();
        if (scope) params.set("scope", scope);
        params.set("active_only", activeOnly ? "true" : "false");

        const headers = await rbacHeaders();
        const resp = await fetchWithTimeout(
            `${window.ROOT_PATH}/rbac/roles?${params.toString()}`,
            { headers },
        );

        if (resp.status === 403) {
            renderRbacAccessRestricted(container, "admin.user_management");
            if (countEl) countEl.textContent = "0";
            return;
        }

        if (!resp.ok) {
            const err = await safeJson(resp);
            throw new Error(err?.detail || `Failed to load roles`);
        }

        const roles = await resp.json();

        // ✅ cache roles
        window.__rbacState.rolesCache = roles || [];

        // ✅ build roleId → roleName map (IMPORTANT for assignments tab)
        window._rbacRoleMap = {};
        roles.forEach(r => {
            if (r.id && r.name) {
                window._rbacRoleMap[r.id] = r.name;
            }
        });

        // ✅ update count
        if (countEl) {
            countEl.textContent = String(roles.length);
        }

        renderRBACRolesTable(roles);
        filterRBACRoles();
    } catch (e) {
        console.error("RBAC roles load failed:", e);
        renderRbacInlineError(container, e.message);
        if (countEl) countEl.textContent = "0";
    }
}


function renderRBACRolesTable(roles) {
    const container = safeGetElement("rbac-roles-container");
    if (!container) return;

    if (!roles || !roles.length) {
        container.innerHTML =
            `<div class="text-gray-500 dark:text-gray-400">No roles found.</div>`;
        return;
    }

    container.innerHTML = `
      <div class="overflow-x-auto rounded-lg ring-1 ring-gray-200 dark:ring-gray-700">
        <table class="min-w-full text-sm">
          <thead class="bg-indigo-50/60 dark:bg-indigo-900/20">
            <tr class="text-left text-gray-700 dark:text-gray-200">
              <th class="px-3 py-2 font-semibold">Name</th>
              <th class="px-3 py-2 font-semibold">Scope</th>
              <th class="px-3 py-2 font-semibold">Permissions</th>
              <th class="px-3 py-2 font-semibold">Type</th>
              <th class="px-3 py-2 font-semibold text-right">Action</th>
            </tr>
          </thead>
          <tbody>
            ${roles.map(role => {
                const isSystem = !!role.is_system_role;
                const permsCount = role.permissions?.length ?? 0;

                return `
                  <tr class="border-t border-gray-200 dark:border-gray-700">
                    <td class="px-3 py-2 font-medium text-gray-900 dark:text-gray-100">
                      ${escapeHtml(role.name)}
                    </td>
                    <td class="px-3 py-2 font-mono text-gray-700 dark:text-gray-300">
                      ${escapeHtml(role.scope)}
                    </td>
                    <td class="px-3 py-2 text-xs text-gray-700 dark:text-gray-300">
                      ${permsCount}
                    </td>
                    <td class="px-3 py-2">
                      ${
                        isSystem
                          ? `<span class="text-xs px-2 py-1 rounded bg-gray-200 dark:bg-gray-700">
                               System
                             </span>`
                          : `<span class="text-xs px-2 py-1 rounded bg-indigo-100 dark:bg-indigo-900/30">
                               Custom
                             </span>`
                      }
                    </td>
                    <td class="px-3 py-2 text-right">
                      ${
                        isSystem
                          ? `<span class="text-xs text-gray-400">Locked</span>`
                          : `
                            <button
                              class="px-3 py-1.5 rounded-md text-xs text-white bg-red-600 hover:bg-red-700"
                              onclick="deleteRole('${escapeJs(role.id)}','${escapeJs(role.name)}')">
                              Delete
                            </button>
                          `
                      }
                    </td>
                  </tr>
                `;
            }).join("")}
          </tbody>
        </table>
      </div>
    `;
}

async function deleteRole(roleId, roleName) {
    if (!confirm(`Delete role "${roleName}"?\n\nThis action cannot be undone.`)) {
        return;
    }

    try {
        const headers = await rbacHeaders();

        const resp = await fetchWithTimeout(
            `${window.ROOT_PATH}/rbac/roles/${encodeURIComponent(roleId)}`,
            {
                method: "DELETE",
                headers,
            },
        );

        if (!resp.ok) {
            const err = await safeJson(resp);
            throw new Error(err?.detail || "Failed to delete role");
        }

        showErrorMessage(`Role "${roleName}" deleted successfully.`);
        await loadRBACRoles();
    } catch (e) {
        console.error("deleteRole failed:", e);
        showErrorMessage(e.message || "Failed to delete role");
    }
}


function filterRBACRoles() {
    const q = (safeGetElement("rbac-roles-search")?.value || "").toLowerCase().trim();
    const roles = window.__rbacState.rolesCache || [];
    if (!q) return renderRBACRolesTable(roles);

    const filtered = roles.filter((r) => {
        const hay = `${r.name || ""} ${r.description || ""} ${r.scope || ""}`.toLowerCase();
        return hay.includes(q);
    });
    renderRBACRolesTable(filtered);
}

function safeExists(id) {
  return !!document.getElementById(id);
}



/** Dropdowns **/
async function loadRBACRoleDropdown() {
    const sel = document.getElementById("rbac-assign-role");
    if (!sel) return;

    if (!window.__rbacState.canUserManage) {
        sel.innerHTML = `<option value="">Access restricted</option>`;
        return;
    }

    try {
        const headers = await rbacHeaders();
        const resp = await fetchWithTimeout(`${window.ROOT_PATH}/rbac/roles?active_only=true`, { headers });

        if (!resp.ok) {
            const err = await safeJson(resp);
            throw new Error(err?.detail || `Failed to load roles: HTTP ${resp.status}`);
        }

        const roles = await resp.json();
        // ---- Build roleId → roleName map (GLOBAL) ----
        window._rbacRoleMap = window._rbacRoleMap || {};

        roles.forEach((role) => {
            window._rbacRoleMap[role.id] = role.name;
        });

        sel.innerHTML =
            `<option value="">Select a role...</option>` +
            (roles || [])
                .map((r) => `<option value="${escapeHtml(r.id || "")}">${escapeHtml(r.name || "")} (${escapeHtml(r.scope || "")})</option>`)
                .join("");
    } catch (e) {
        console.error("RBAC role dropdown failed:", e);
        sel.innerHTML = `<option value="">Error loading roles</option>`;
    }
}

async function loadRBACPermissionsDropdown() {
    const sel = safeGetElement("perm-audit-check-perms");
    if (!sel) return;

    if (!window.__rbacState.canAudit) {
        sel.innerHTML = `<option value="">Access restricted</option>`;
        return;
    }

    try {
        if (!window.__rbacState.allPermissionsCache) {
            const headers = await rbacHeaders();
            const resp = await fetchWithTimeout(`${window.ROOT_PATH}/rbac/permissions/available`, { headers });
            if (!resp.ok) {
                const err = await safeJson(resp);
                throw new Error(err?.detail || `Failed to load permissions: HTTP ${resp.status}`);
            }
            const data = await resp.json();
            window.__rbacState.allPermissionsCache = data?.all_permissions || [];
        }

        const perms = window.__rbacState.allPermissionsCache || [];
        sel.innerHTML =
            `<option value="">Select a permission...</option>` +
            perms.map((p) => `<option value="${escapeHtml(p)}">${escapeHtml(p)}</option>`).join("");
    } catch (e) {
        console.error("RBAC permissions dropdown failed:", e);
        sel.innerHTML = `<option value="">Error loading permissions</option>`;
    }
}


async function loadRbacUsersDropdown(selectId) {
  const sel = safeGetElement(selectId);
  if (!sel) return;

  sel.innerHTML = `<option value="">Loading users...</option>`;

  try {
    const headers = await rbacHeaders();
    const resp = await fetchWithTimeout(
      `${window.ROOT_PATH}/auth/email/admin/users?limit=200&offset=0`,
      { headers }
    );

    if (!resp.ok) {
      const err = await safeJson(resp);
      throw new Error(err?.detail || `Failed: HTTP ${resp.status}`);
    }

    const data = await resp.json();
    const emails = (data.users || [])
      .map((u) => (u.email || "").trim())
      .filter(Boolean)
      .map((e) => e.toLowerCase());

    const unique = Array.from(new Set(emails)).sort();

    sel.innerHTML = unique.length
      ? [`<option value="">Select a user...</option>`]
          .concat(unique.map((e) => `<option value="${escapeHtml(e)}">${escapeHtml(e)}</option>`))
          .join("")
      : `<option value="">No users found</option>`;
  } catch (e) {
    console.error("loadRbacUsersDropdown failed:", e);
    sel.innerHTML = `<option value="">Failed to load users</option>`;
  }
}


async function loadRbacRolesDropdown(selectId) {
  const sel = safeGetElement(selectId);
  if (!sel) return;

  sel.innerHTML = `<option value="">Loading roles...</option>`;

  try {
    const headers = await rbacHeaders();
    const resp = await fetchWithTimeout(`${window.ROOT_PATH}/rbac/roles?active_only=true`, { headers });

    if (!resp.ok) {
      const err = await safeJson(resp);
      throw new Error(err?.detail || `Failed: HTTP ${resp.status}`);
    }

    const roles = await resp.json();

    sel.innerHTML = roles.length
      ? [`<option value="">Select a role...</option>`]
          .concat(
            roles
              .slice()
              .sort((a, b) => String(a.name).localeCompare(String(b.name)))
              .map((r) => `<option value="${escapeHtml(r.id)}">${escapeHtml(r.name)}${r.scope ? ` • ${escapeHtml(r.scope)}` : ""}</option>`)
          )
          .join("")
      : `<option value="">No roles found</option>`;
  } catch (e) {
    console.error("loadRbacRolesDropdown failed:", e);
    sel.innerHTML = `<option value="">Failed to load roles</option>`;
  }
}

async function refreshRBACUserRoleAssignments() {
  const status = safeGetElement("rbac-assign-status");

  try {
    // ✅ users dropdown for this tab
    if (typeof window.loadRbacUsersDropdown === "function") {
      await window.loadRbacUsersDropdown("rbac-assign-user-email");
    } else if (typeof loadRbacUsersDropdown === "function") {
      await loadRbacUsersDropdown("rbac-assign-user-email");
    }

    // ✅ roles dropdown for this tab (your function name)
    if (typeof window.loadRBACUserRoles === "function") {
      await window.loadRBACUserRoles("rbac-assign-role-id");
    } else if (typeof loadRBACUserRoles === "function") {
      await loadRBACUserRoles("rbac-assign-role-id");
    }

    // ✅ refresh assignments list only if a user is selected
    const email = (safeGetElement("rbac-assign-user-email")?.value || "").trim();
    if (email) {
      await loadUserRoleAssignments();
    }
  } catch (e) {
    console.error("refreshRBACUserRoleAssignments failed:", e);
    if (status) {
      status.innerHTML = `<span class="text-red-600">${escapeHtml(e.message || "Refresh failed")}</span>`;
    }
  }
}

async function loadUserRoleAssignments() {
  const email = (safeGetElement("rbac-assign-user-email")?.value || "").trim();
  const list = safeGetElement("rbac-assignments-list");
  const count = safeGetElement("rbac-assignments-count");
  const status = safeGetElement("rbac-assign-status");

  // ❌ DO NOT clear status here

  if (!list || !count) return;

  if (!email) {
    list.innerHTML = `<div class="text-gray-500 dark:text-gray-400">No user selected.</div>`;
    count.textContent = "0";
    return;
  }

  try {
    list.innerHTML = `<div class="text-gray-500 dark:text-gray-400"><span class="animate-pulse">Loading...</span></div>`;
    count.textContent = "…";

    const headers = await rbacHeaders();
    const resp = await fetchWithTimeout(
      `${window.ROOT_PATH}/rbac/users/${encodeURIComponent(email)}/roles?active_only=true`,
      { headers }
    );

    if (!resp.ok) {
      const err = await safeJson(resp);
      throw new Error(err?.detail || `Failed: HTTP ${resp.status}`);
    }

    const assignments = await resp.json();
    count.textContent = String(assignments.length);

    if (!assignments.length) {
      list.innerHTML = `<div class="text-gray-500 dark:text-gray-400">No assignments found.</div>`;
      return;
    }

    // Render table
    if (!assignments.length) {
      list.innerHTML = `<div class="text-gray-500 dark:text-gray-400">No assignments found.</div>`;
      return;
    }

    list.innerHTML = `
      <div class="overflow-x-auto rounded-lg ring-1 ring-gray-200 dark:ring-gray-700">
        <table class="min-w-full text-sm">
          <thead class="bg-indigo-50/60 dark:bg-indigo-900/20">
            <tr class="text-left text-gray-700 dark:text-gray-200">
              <th class="px-3 py-2 font-semibold">Role</th>
              <th class="px-3 py-2 font-semibold">Scope</th>
              <th class="px-3 py-2 font-semibold">Scope ID</th>
              <th class="px-3 py-2 font-semibold">Expires</th>
              <th class="px-3 py-2 font-semibold">Action</th>
            </tr>
          </thead>
          <tbody>
            ${assignments.map((a) => {
              const roleName = window._rbacRoleMap?.[a.role_id] || a.role_name || a.role?.name || a.role_id || a.roleId || "—";
              const scope = a.scope || "—";
              const scopeId = a.scope_id || "—";
              const expires = a.expires_at ? formatIsoToLocal(a.expires_at) : "—";

              return `
                <tr class="border-t border-gray-200 dark:border-gray-700">
                  <td class="px-3 py-2 text-gray-900 dark:text-gray-100">${escapeHtml(roleName)}</td>
                  <td class="px-3 py-2 font-mono text-gray-800 dark:text-gray-200">${escapeHtml(scope)}</td>
                  <td class="px-3 py-2 font-mono text-gray-800 dark:text-gray-200 break-all">${escapeHtml(scopeId)}</td>
                  <td class="px-3 py-2 text-gray-800 dark:text-gray-200">${escapeHtml(expires)}</td>
                  <td class="px-3 py-2">
                    <button class="px-3 py-1.5 rounded-md text-white bg-red-600 hover:bg-red-700"
                      onclick="revokeUserRole('${escapeJs(email)}','${escapeJs(a.role_id)}','${escapeJs(a.scope || "")}','${escapeJs(a.scope_id || "")}')">
                      Revoke
                    </button>
                  </td>
                </tr>
              `;
            }).join("")}
          </tbody>
        </table>
      </div>
    `;
  } catch (e) {
    console.error("loadUserRoleAssignments failed:", e);
    count.textContent = "0";
    list.innerHTML = `<div class="text-red-600">${escapeHtml(e.message)}</div>`;
  }
}



function formatIsoToLocal(iso) {
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleString();
  } catch {
    return iso;
  }
}


async function assignRoleToSelectedUser() {
    const email = (safeGetElement("rbac-assign-user-email")?.value || "").trim();
    const roleId = (safeGetElement("rbac-assign-role-id")?.value || "").trim();
    const scope = (safeGetElement("rbac-assign-scope")?.value || "global").trim();
    const scopeId = (safeGetElement("rbac-assign-scope-id")?.value || "").trim();

    // --- EXPIRY HANDLING (date optional, time defaults to end-of-day) ---
    const expiryDateEl = safeGetElement("rbac-assign-expiry-date");
    const expiryTimeEl = safeGetElement("rbac-assign-expiry-time");

    let expiresAt = null;
    if (expiryDateEl && expiryDateEl.value) {
        const time =
            expiryTimeEl && expiryTimeEl.value ? expiryTimeEl.value : "23:59";
        const local = new Date(`${expiryDateEl.value}T${time}:00`);
        if (!isNaN(local.getTime())) {
            expiresAt = local.toISOString();
        }
    }

    const status = safeGetElement("rbac-assign-status");
    if (status) status.innerHTML = "";

    if (!email) return showInlineStatus(status, "Please select a user.", "error");
    if (!roleId) return showInlineStatus(status, "Please select a role.", "error");

    try {
        showInlineStatus(status, "Assigning role...", "loading");

        // ✅ Must match UserRoleAssignRequest exactly (router adds granted_by from auth user)
        const payload = {
            role_id: roleId,
            scope: scope,
            scope_id: scope === "team" ? (scopeId || null) : null,
            expires_at: expiresAt,
        };

        console.log("Assign role payload:", payload);

        // ✅ IMPORTANT: force Content-Type so FastAPI parses JSON
        const headers = {
            ...(await rbacHeaders()),
            "Content-Type": "application/json",
        };

        const resp = await fetchWithTimeout(
            `${window.ROOT_PATH}/rbac/users/${encodeURIComponent(email)}/roles`,
            {
                method: "POST",
                headers,
                body: JSON.stringify(payload),
            },
        );

        if (!resp.ok) {
            const err = await safeJson(resp);
            let message;

            if (Array.isArray(err?.detail)) {
                message = err.detail
                    .map((d) => d?.msg || JSON.stringify(d))
                    .join("; ");
            } else if (typeof err?.detail === "object") {
                message = JSON.stringify(err.detail);
            } else {
                message = err?.detail || `Failed: HTTP ${resp.status}`;
            }

            throw new Error(message);
        }

        showInlineStatus(status, "✅ Role assigned successfully.", "success");

        // Refresh user role assignments list
        if (typeof loadUserRoleAssignments === "function") {
            await loadUserRoleAssignments();
        } else if (typeof loadRBACUserRoles === "function") {
            await loadRBACUserRoles();
        }
    } catch (e) {
        console.error("assignRoleToSelectedUser failed:", e);
        showInlineStatus(status, e.message || "Unexpected error", "error");
    }
}

function showInlineStatus(el, message, type = "info") {
    if (!el) return;

    // Clear previous timers
    if (el._dismissTimer) {
        clearTimeout(el._dismissTimer);
        delete el._dismissTimer;
    }

    el.textContent = message;
    el.style.display = "block";

    // Reset base classes
    el.className = "text-sm px-3 py-2 rounded-md ring-1";

    if (type === "success") {
        el.classList.add(
            "bg-green-50",
            "text-green-800",
            "ring-green-200",
            "dark:bg-green-900/20",
            "dark:text-green-200",
            "dark:ring-green-800/40"
        );

        // ✅ Auto-dismiss after 3 seconds
        el._dismissTimer = setTimeout(() => {
            el.textContent = "";
            el.style.display = "none";
            delete el._dismissTimer;
        }, 3000);
    }

    if (type === "error") {
        el.classList.add(
            "bg-red-50",
            "text-red-800",
            "ring-red-200",
            "dark:bg-red-900/20",
            "dark:text-red-200",
            "dark:ring-red-800/40"
        );
    }

    if (type === "loading") {
        el.classList.add(
            "bg-yellow-50",
            "text-yellow-800",
            "ring-yellow-200",
            "dark:bg-yellow-900/20",
            "dark:text-yellow-200",
            "dark:ring-yellow-800/40"
        );
    }
}


/** Assignments **/
function toggleRBACScopeId() {
    const scope = safeGetElement("rbac-assign-scope")?.value;
    const wrap = safeGetElement("rbac-assign-scope-id-wrap");
    if (!wrap) return;
    if (scope === "team") wrap.classList.remove("hidden");
    else wrap.classList.add("hidden");
}

async function loadRBACUserRoles() {
    const container = safeGetElement("rbac-user-roles-container");
    if (!container) return;

    if (!window.__rbacState.canUserManage) {
        renderRbacAccessRestricted(container, "admin.user_management");
        return;
    }

    const email = (safeGetElement("rbac-user-email")?.value || "").trim();
    if (!email) {
        container.innerHTML = `<div class="text-gray-500 dark:text-gray-400">Enter a user email and click Load.</div>`;
        return;
    }

    try {
        container.innerHTML = `<p class="text-gray-500 dark:text-gray-400">Loading assignments...</p>`;
        const headers = await rbacHeaders();

        const resp = await fetchWithTimeout(
            `${window.ROOT_PATH}/rbac/users/${encodeURIComponent(email)}/roles?active_only=true`,
            { headers }
        );

        if (!resp.ok) {
            const err = await safeJson(resp);
            throw new Error(err?.detail || `Failed to load assignments: HTTP ${resp.status}`);
        }

        const assignments = await resp.json();
        renderRBACUserAssignmentsTable(email, assignments || []);
    } catch (e) {
        console.error("RBAC user roles failed:", e);
        renderRbacInlineError(container, e.message);
    }
}

function renderRBACUserAssignmentsTable(userEmail, rows) {
    const container = safeGetElement("rbac-user-roles-container");
    if (!container) return;

    if (!rows || rows.length === 0) {
        container.innerHTML = `<div class="text-gray-500 dark:text-gray-400">No active role assignments found.</div>`;
        return;
    }

    const body = rows.map((ur) => {
        const roleId = escapeHtml(ur.role_id || ur.role?.id || "");
        const roleName = escapeHtml(ur.role_name || ur.role?.name || roleId);
        const scope = escapeHtml(ur.scope || "");
        const scopeId = escapeHtml(ur.scope_id || "");
        const expiresAt = escapeHtml(ur.expires_at || "Never");

        return `
          <tr class="border-t border-gray-200 dark:border-gray-700">
            <td class="px-3 py-2 font-medium text-gray-900 dark:text-gray-100">${roleName}</td>
            <td class="px-3 py-2 text-gray-700 dark:text-gray-300">${scope}</td>
            <td class="px-3 py-2 text-gray-700 dark:text-gray-300">${scopeId || "-"}</td>
            <td class="px-3 py-2 text-gray-600 dark:text-gray-400">${expiresAt}</td>
            <td class="px-3 py-2 text-right">
              <button type="button"
                class="px-3 py-1 rounded bg-red-600 text-white hover:bg-red-700"
                onclick="revokeRBACUserRole('${escapeHtml(userEmail)}','${roleId}','${scope}','${scopeId}')">
                Revoke
              </button>
            </td>
          </tr>
        `;
    }).join("");

    container.innerHTML = `
      <div class="overflow-x-auto">
        <table class="min-w-full text-sm">
          <thead class="bg-gray-50 dark:bg-gray-900/30">
            <tr class="text-left text-gray-700 dark:text-gray-300">
              <th class="px-3 py-2">Role</th>
              <th class="px-3 py-2">Scope</th>
              <th class="px-3 py-2">Scope ID</th>
              <th class="px-3 py-2">Expires</th>
              <th class="px-3 py-2 text-right">Action</th>
            </tr>
          </thead>
          <tbody>${body}</tbody>
        </table>
      </div>
    `;
}

async function assignRBACRoleToUser() {
    const errBox = safeGetElement("rbac-assign-error");
    if (errBox) errBox.innerHTML = "";

    const email = (safeGetElement("rbac-user-email")?.value || "").trim();
    const roleId = safeGetElement("rbac-assign-role")?.value || "";
    const scope = safeGetElement("rbac-assign-scope")?.value || "global";
    const scopeId = (safeGetElement("rbac-assign-scope-id")?.value || "").trim();
    const expiresLocal = safeGetElement("rbac-assign-expires-at")?.value || "";

    const expiryDate = (safeGetElement("rbac-assign-expiry-date")?.value || "").trim();
    let expiryTime = (safeGetElement("rbac-assign-expiry-time")?.value || "").trim();

    // If date is blank => no expiry no matter what time says
    let expiresAtIso = null;

    if (expiryDate) {
        // If time blank, force end of day
        if (!expiryTime) expiryTime = "23:59";

        // Build a local datetime and convert to ISO
        // (This keeps the user experience "end of day local time")
        const local = new Date(`${expiryDate}T${expiryTime}:00`);
        if (!isNaN(local.getTime())) {
            expiresAtIso = local.toISOString();
        }
    }

    if (scope === "team" && !scopeId) return showErrorMessage("Scope ID (Team ID) is required for team scope.", "rbac-assign-error");

    const payload = {
        role_id: roleId,
        scope: scope,
        scope_id: scope === "team" ? scopeId : null,
        expires_at: expiresLocal ? new Date(expiresLocal).toISOString() : null,
    };

    try {
        const headers = await rbacHeaders();
        const resp = await fetchWithTimeout(
            `${window.ROOT_PATH}/rbac/users/${encodeURIComponent(email)}/roles`,
            { method: "POST", headers, body: JSON.stringify(payload) }
        );

        if (!resp.ok) {
            const err = await safeJson(resp);
            return showErrorMessage(err?.detail || `Failed: HTTP ${resp.status}`, "rbac-assign-error");
        }

        const msg = safeGetElement("rbac-messages");
        if (msg) {
            msg.innerHTML = `<div class="text-green-700 dark:text-green-300 text-sm">✓ Role assigned successfully</div>`;
            setTimeout(() => { if (msg) msg.innerHTML = ""; }, 2500);
        }
        loadRBACUserRoles();
    } catch (e) {
        console.error("RBAC assign failed:", e);
        showErrorMessage(e.message || "Failed to assign role", "rbac-assign-error");
    }
}

async function revokeUserRole(userEmail, roleId, scope = null, scopeId = null) {
    try {
        const headers = {
            Authorization: `Bearer ${await getAuthToken()}`,
            "Content-Type": "application/json",
        };

        const qs = new URLSearchParams();
        if (scope) qs.set("scope", scope);
        if (scopeId) qs.set("scope_id", scopeId);

        const url = `${window.ROOT_PATH}/rbac/users/${encodeURIComponent(
            userEmail,
        )}/roles/${encodeURIComponent(roleId)}?${qs.toString()}`;

        const resp = await fetchWithTimeout(url, { method: "DELETE", headers });

        if (!resp.ok) {
            const err = await safeJson(resp);
            const detail =
                (err && (err.detail || err.message)) ||
                `HTTP ${resp.status} ${resp.statusText}`;
            throw new Error(`Failed to revoke role: ${detail}`);
        }

        showSuccessMessage("✓ Role revoked successfully", "rbac-messages");

        // Refresh assignments list safely (if you have a loader)
        if (typeof loadUserRoleAssignments === "function") {
            await loadUserRoleAssignments();
        } else if (typeof loadRBACUserRoles === "function") {
            await loadRBACUserRoles();
        }
    } catch (e) {
        console.error("revokeUserRole failed:", e);
        showErrorMessage(e.message || "Failed to revoke role", "rbac-messages");
    }
}



/** Audit **/
async function loadRBACUserPermissions() {
    const container = safeGetElement("rbac-audit-perms-container");
    if (!container) return;

    if (!window.__rbacState.canAudit) {
        renderRbacAccessRestricted(container, "admin.security_audit");
        return;
    }

    const email = (safeGetElement("rbac-audit-user-email")?.value || "").trim();
    const teamId = (safeGetElement("rbac-audit-team-id")?.value || "").trim();
    if (!email) {
        container.innerHTML = `<div class="text-gray-500 dark:text-gray-400">Enter a user email and click Load.</div>`;
        return;
    }

    try {
        container.innerHTML = `<p class="text-gray-500 dark:text-gray-400">Loading permissions...</p>`;
        const headers = await rbacHeaders();
        const qs = new URLSearchParams();
        if (teamId) qs.set("team_id", teamId);

        const resp = await fetchWithTimeout(
            `${window.ROOT_PATH}/rbac/permissions/user/${encodeURIComponent(email)}?${qs.toString()}`,
            { headers }
        );

        if (!resp.ok) {
            const err = await safeJson(resp);
            throw new Error(err?.detail || `Failed: HTTP ${resp.status}`);
        }

        const perms = await resp.json();
        container.innerHTML = renderPermissionList(perms || []);
    } catch (e) {
        console.error("RBAC audit perms failed:", e);
        renderRbacInlineError(container, e.message);
    }
}

function enableClickToggleMultiSelect(selectId, countBadgeId = null) {
  const sel = safeGetElement(selectId);
  if (!sel) return;

  // Prevent double-binding
  if (sel.__clickToggleBound) return;
  sel.__clickToggleBound = true;

  // Click toggles selection without requiring Ctrl/Cmd
  sel.addEventListener("mousedown", (e) => {
    const opt = e.target;
    if (!opt || opt.tagName !== "OPTION") return;

    e.preventDefault(); // stops the browser's default selection model
    opt.selected = !opt.selected;

    // Keep focus for keyboard users
    sel.focus();

    // Update count badge if present
    if (countBadgeId) {
      const badge = safeGetElement(countBadgeId);
      if (badge) {
        const n = Array.from(sel.selectedOptions || []).length;
        badge.textContent = `${n} selected`;
      }
    }

    // Trigger change for any downstream logic
    sel.dispatchEvent(new Event("change", { bubbles: true }));
  });

  // Also update badge on keyboard selection changes
  if (countBadgeId) {
    sel.addEventListener("change", () => {
      const badge = safeGetElement(countBadgeId);
      if (badge) {
        const n = Array.from(sel.selectedOptions || []).length;
        badge.textContent = `${n} selected`;
      }
    });
  }
}


function renderRbacChips(perms) {
  if (!perms || perms.length === 0) {
    return `<div class="text-gray-500 dark:text-gray-400 text-sm">No permissions found.</div>`;
  }

  // Group by prefix
  const groups = {};
  perms.forEach((p) => {
    const s = String(p);
    const prefix = s.includes(".") ? s.split(".")[0] : "misc";
    groups[prefix] = groups[prefix] || [];
    groups[prefix].push(s);
  });

  const ordered = Object.keys(groups).sort();

  const sections = ordered.map((k) => {
    const chips = groups[k].sort().map((perm) => `
      <span class="inline-flex items-center px-2 py-1 rounded-md text-xs font-mono
        bg-indigo-50 text-indigo-800 ring-1 ring-indigo-200
        dark:bg-indigo-900/20 dark:text-indigo-200 dark:ring-indigo-800/40
        max-w-full break-all">
        ${escapeHtml(perm)}
      </span>
    `).join("");

    return `
      <div class="mb-4">
        <div class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">${escapeHtml(k)}</div>
        <div class="flex flex-wrap gap-2 max-w-full">${chips}</div>
      </div>
    `;
  }).join("");

  return `<div class="max-h-[420px] overflow-y-auto px-1 pr-2">${sections}</div>`;
}

function renderPermissionCheckTable(rows) {
  if (!rows || rows.length === 0) {
    return `<div class="text-gray-500 dark:text-gray-400 text-sm">No results.</div>`;
  }

  const body = rows.map((r) => {
    const granted = !!r.granted;
    const badge = granted
      ? `<span class="inline-flex items-center px-2 py-1 rounded-full text-xs bg-green-50 text-green-700 ring-1 ring-green-200 dark:bg-green-900/20 dark:text-green-300 dark:ring-green-800/40">Granted</span>`
      : `<span class="inline-flex items-center px-2 py-1 rounded-full text-xs bg-red-50 text-red-700 ring-1 ring-red-200 dark:bg-red-900/20 dark:text-red-300 dark:ring-red-800/40">Denied</span>`;

    return `
      <tr class="border-t border-gray-200 dark:border-gray-700">
        <td class="px-3 py-2 text-sm text-gray-900 dark:text-gray-100 font-mono break-all">${escapeHtml(r.permission)}</td>
        <td class="px-3 py-2">${badge}</td>
      </tr>
    `;
  }).join("");

  return `
    <div class="overflow-x-auto rounded-lg ring-1 ring-gray-200 dark:ring-gray-700">
      <table class="min-w-full text-sm">
        <thead class="bg-indigo-50/60 dark:bg-indigo-900/20">
          <tr class="text-left text-gray-700 dark:text-gray-200">
            <th class="px-3 py-2 font-semibold">Permission</th>
            <th class="px-3 py-2 font-semibold">Decision</th>
          </tr>
        </thead>
        <tbody>${body}</tbody>
      </table>
    </div>
  `;
}

async function loadAuditUserDropdowns() {
  const sel1 = safeGetElement("perm-audit-effective-email");
  const sel2 = safeGetElement("perm-audit-check-email");
  if (!sel1 || !sel2) return;

  try {
    sel1.innerHTML = `<option value="">Loading users...</option>`;
    sel2.innerHTML = `<option value="">Loading users...</option>`;

    const headers = await rbacHeaders(); // already includes Bearer token correctly
    const resp = await fetchWithTimeout(
      `${window.ROOT_PATH}/auth/email/admin/users?limit=200&offset=0`,
      { headers }
    );

    if (!resp.ok) {
      const err = await safeJson(resp);
      throw new Error(err?.detail || `Failed: HTTP ${resp.status}`);
    }

    const data = await resp.json();
    const users = (data.users || []);
    const emails = users
      .map((u) => (u.email || "").trim())
      .filter(Boolean)
      .map((e) => e.toLowerCase());

    const unique = Array.from(new Set(emails)).sort();

    const options = unique.length
      ? [`<option value="">Select a user...</option>`]
          .concat(unique.map((e) => `<option value="${escapeHtml(e)}">${escapeHtml(e)}</option>`))
          .join("")
      : `<option value="">No users found</option>`;

    sel1.innerHTML = options;
    sel2.innerHTML = options;
  } catch (e) {
    console.error("loadAuditUserDropdowns failed:", e);
    sel1.innerHTML = `<option value="">Failed to load users</option>`;
    sel2.innerHTML = `<option value="">Failed to load users</option>`;
  }
}



function extractEmailsFromHtml(html) {
  try {
    // Try robust parsing
    const doc = new DOMParser().parseFromString(html, "text/html");
    const text = doc.body ? doc.body.textContent : html;
    const re = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
    const matches = (text.match(re) || []).map((s) => s.toLowerCase());
    return Array.from(new Set(matches)).sort();
  } catch (_e) {
    return [];
  }
}

async function loadAuditPermissionsDropdown() {
  const sel = safeGetElement("perm-audit-check-perms");
  if (!sel) return;

  try {
    const headers = await rbacHeaders();
    const resp = await fetchWithTimeout(`${window.ROOT_PATH}/rbac/permissions/available`, { headers });

    if (!resp.ok) {
      const err = await safeJson(resp);
      throw new Error(err?.detail || `Failed to load permissions: HTTP ${resp.status}`);
    }

    const data = await resp.json();
    const byRes = data.permissions_by_resource || {};
    const keys = Object.keys(byRes).sort();

    const groupsHtml = keys.map((k) => {
      const items = (byRes[k] || []).slice().sort()
        .map((p) => `<option value="${escapeHtml(p)}">${escapeHtml(p)}</option>`)
        .join("");
      return `<optgroup label="${escapeHtml(k)}">${items}</optgroup>`;
    }).join("");

    sel.innerHTML = groupsHtml || `<option value="">No permissions available</option>`;
  } catch (e) {
    console.error("loadAuditPermissionsDropdown failed:", e);
    sel.innerHTML = `<option value="">Failed to load permissions</option>`;
  }
}


async function runEffectivePermissionsAudit() {
  const email = (safeGetElement("perm-audit-effective-email")?.value || "").trim();
  const team = (safeGetElement("perm-audit-effective-team")?.value || "").trim();
  const out = safeGetElement("perm-audit-effective-results");
  const badge = safeGetElement("perm-audit-effective-count");

  if (!out) return;

  if (!email) {
    out.innerHTML = `<div class="text-red-600 text-sm">Please select a user email.</div>`;
    if (badge) badge.textContent = "0";
    return;
  }

  try {
    out.innerHTML = `<p class="text-gray-500 dark:text-gray-400"><span class="animate-pulse">Loading...</span></p>`;
    if (badge) badge.textContent = "…";

    const qs = new URLSearchParams();
    if (team) qs.set("team_id", team);

    const headers = await rbacHeaders();
    const resp = await fetchWithTimeout(
      `${window.ROOT_PATH}/rbac/permissions/user/${encodeURIComponent(email)}?${qs.toString()}`,
      { headers }
    );

    if (!resp.ok) {
      const err = await safeJson(resp);
      throw new Error(err?.detail || `Failed: HTTP ${resp.status}`);
    }

    const perms = await resp.json();
    const list = (perms || []).slice().sort();

    if (badge) badge.textContent = String(list.length);
    out.innerHTML = renderRbacChips(list);
  } catch (e) {
    console.error("Effective permissions audit failed:", e);
    if (badge) badge.textContent = "0";
    out.innerHTML = `<div class="text-red-600 text-sm">${escapeHtml(e.message)}</div>`;
  }
}


function getSelectedValues(selectEl) {
  if (!selectEl) return [];
  return Array.from(selectEl.selectedOptions || []).map((o) => o.value).filter(Boolean);
}

async function runPermissionChecksBatch() {
  const email = (safeGetElement("perm-audit-check-email")?.value || "").trim();
  const permsSel = safeGetElement("perm-audit-check-perms");
  const perms = getSelectedValues(permsSel);
  const teamId = (safeGetElement("perm-audit-check-team")?.value || "").trim();
  const out = safeGetElement("perm-audit-check-results");

  if (!out) return;

  if (!email) {
    out.innerHTML = `<div class="text-red-600 text-sm">Please select a user email.</div>`;
    return;
  }
  if (perms.length === 0) {
    out.innerHTML = `<div class="text-red-600 text-sm">Please select at least one permission.</div>`;
    return;
  }

  out.innerHTML = `<p class="text-gray-500 dark:text-gray-400"><span class="animate-pulse">Running checks...</span></p>`;

  try {
    const headers = await rbacHeaders();
    const rows = [];

    for (const perm of perms) {
      const payload = {
        user_email: email,
        permission: perm,
        team_id: teamId || null,
        resource_type: null,
        resource_id: null,
      };

      const resp = await fetchWithTimeout(`${window.ROOT_PATH}/rbac/permissions/check`, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
      });

      if (!resp.ok) {
        const err = await safeJson(resp);
        throw new Error(err?.detail || `Check failed for ${perm}: HTTP ${resp.status}`);
      }

      const result = await resp.json();
      rows.push({ permission: perm, granted: !!result.granted });
    }

    out.innerHTML = renderPermissionCheckTable(rows);
  } catch (e) {
    console.error("Permission checks failed:", e);
    out.innerHTML = `<div class="text-red-600 text-sm">${escapeHtml(e.message)}</div>`;
  }
}

function clearPermissionCheckResults() {
  const out = safeGetElement("perm-audit-check-results");
  if (out) out.innerHTML = `<div class="text-gray-500 dark:text-gray-400 text-sm">No checks run yet.</div>`;
}


async function checkRBACPermission() {
    const result = safeGetElement("rbac-check-result");
    if (!result) return;

    if (!window.__rbacState.canAudit) {
        renderRbacAccessRestricted(result, "admin.security_audit");
        return;
    }

    const errBox = safeGetElement("rbac-check-error");
    if (errBox) errBox.innerHTML = "";

    const userEmail = (safeGetElement("rbac-check-user-email")?.value || "").trim();
    const permission = (safeGetElement("perm-audit-check-perms")?.value || "").trim();
    const resourceType = (safeGetElement("rbac-check-resource-type")?.value || "").trim();
    const resourceId = (safeGetElement("rbac-check-resource-id")?.value || "").trim();
    const teamId = (safeGetElement("rbac-check-team-id")?.value || "").trim();

    if (!userEmail) return showErrorMessage("User email is required.", "rbac-check-error");
    if (!permission) return showErrorMessage("Permission is required.", "rbac-check-error");

    const payload = {
        user_email: userEmail,
        permission: permission,
        resource_type: resourceType || null,
        resource_id: resourceId || null,
        team_id: teamId || null,
    };

    try {
        result.innerHTML = `<p class="text-gray-500 dark:text-gray-400">Checking...</p>`;
        const headers = await rbacHeaders();

        const resp = await fetchWithTimeout(`${window.ROOT_PATH}/rbac/permissions/check`, {
            method: "POST",
            headers,
            body: JSON.stringify(payload),
        });

        if (!resp.ok) {
            const err = await safeJson(resp);
            showErrorMessage(err?.detail || `Check failed: HTTP ${resp.status}`, "rbac-check-error");
            result.innerHTML = `<div class="text-gray-500 dark:text-gray-400">No result.</div>`;
            return;
        }

        const data = await resp.json();
        const granted = !!data.granted;

        result.innerHTML = `
          <div class="rounded-lg p-4 ${
            granted
              ? "border border-green-200 bg-green-50 text-green-900 dark:border-green-900/40 dark:bg-green-900/20 dark:text-green-100"
              : "border border-red-200 bg-red-50 text-red-900 dark:border-red-900/40 dark:bg-red-900/20 dark:text-red-100"
          }">
            <div class="font-semibold mb-1">${granted ? "✅ Granted" : "❌ Denied"}</div>
            <div class="text-sm opacity-90">
              <div><span class="font-medium">User:</span> ${escapeHtml(data.user_email || userEmail)}</div>
              <div><span class="font-medium">Permission:</span> ${escapeHtml(data.permission || permission)}</div>
            </div>
          </div>
        `;
    } catch (e) {
        console.error("RBAC permission check failed:", e);
        showErrorMessage(e.message || "Permission check failed", "rbac-check-error");
        result.innerHTML = `<div class="text-gray-500 dark:text-gray-400">No result.</div>`;
    }
}

/** My Access **/
async function loadRBACMyAccess() {
    await Promise.allSettled([loadRBACMyRoles(), loadRBACMyPermissions()]);
}

async function loadRBACMyRoles() {
  const container = safeGetElement("rbac-my-roles-container");
  const countEl = safeGetElement("rbac-my-roles-count");
  if (!container) return;

  try {
    container.innerHTML = `<p class="text-gray-500 dark:text-gray-400"><span class="animate-pulse">Loading...</span></p>`;
    if (countEl) countEl.textContent = "…";

    // ✅ try to load role id -> name map (best effort)
    await ensureRBACRoleNameMap();

    const headers = await rbacHeaders();
    const resp = await fetchWithTimeout(`${window.ROOT_PATH}/rbac/my/roles`, { headers });

    if (!resp.ok) {
      const err = await safeJson(resp);
      throw new Error(err?.detail || `Failed: HTTP ${resp.status}`);
    }

    const roles = await resp.json();
    if (countEl) countEl.textContent = String((roles || []).length);

    container.innerHTML = renderMyRolesTable(roles || []);
  } catch (e) {
    console.error("RBAC my roles failed:", e);
    if (countEl) countEl.textContent = "0";
    renderRbacInlineError(container, e.message);
  }
}


async function loadRBACMyPermissions() {
  const container = safeGetElement("rbac-my-perms-container");
  const countEl = safeGetElement("rbac-my-perms-count");
  if (!container) return;

  try {
    container.innerHTML = `<p class="text-gray-500 dark:text-gray-400"><span class="animate-pulse">Loading...</span></p>`;
    if (countEl) countEl.textContent = "…";

    const teamId = (safeGetElement("rbac-my-team-id")?.value || "").trim();
    const qs = new URLSearchParams();
    if (teamId) qs.set("team_id", teamId);

    const headers = await rbacHeaders();
    const resp = await fetchWithTimeout(`${window.ROOT_PATH}/rbac/my/permissions?${qs.toString()}`, { headers });

    if (!resp.ok) {
      const err = await safeJson(resp);
      throw new Error(err?.detail || `Failed: HTTP ${resp.status}`);
    }

    const perms = await resp.json();
    window.__rbacState.myPermissionsList = (perms || []).slice().sort();

    if (countEl) countEl.textContent = String(window.__rbacState.myPermissionsList.length);

    // render full list and allow search to filter
    container.innerHTML = renderPermissionsGroupedChips(window.__rbacState.myPermissionsList);
  } catch (e) {
    console.error("RBAC my perms failed:", e);
    if (countEl) countEl.textContent = "0";
    renderRbacInlineError(container, e.message);
  }
}


function renderPermissionsGroupedChips(perms) {
  if (!perms || perms.length === 0) {
    return `<div class="text-gray-500 dark:text-gray-400">No permissions found.</div>`;
  }

  // Group by prefix before first dot: tokens.*, tools.*, admin.*, etc.
  const groups = {};
  perms.forEach((p) => {
    const s = String(p);
    const prefix = s.includes(".") ? s.split(".")[0] : "misc";
    groups[prefix] = groups[prefix] || [];
    groups[prefix].push(s);
  });

  const orderedKeys = Object.keys(groups).sort((a, b) => a.localeCompare(b));

  const sections = orderedKeys.map((k) => {
    const items = groups[k]
      .sort()
      .map((perm) => {
        return `
          <span class="inline-flex items-center px-2 py-1 rounded-md text-xs font-mono
            bg-indigo-50 text-indigo-800 ring-1 ring-indigo-200
            dark:bg-indigo-900/20 dark:text-indigo-200 dark:ring-indigo-800/40
            max-w-full break-all">

            ${escapeHtml(perm)}
          </span>
        `;
      })
      .join("");

    return `
      <div class="mb-4">
        <div class="mb-2">
          <div class="text-sm font-semibold text-gray-900 dark:text-gray-100">
            ${escapeHtml(k)}
          </div>
        </div>
        <div class="flex flex-wrap gap-2 max-w-full">
          ${items}
        </div>
      </div>
    `;
  }).join("");

  return `
    <div class="max-h-[420px] overflow-y-auto px-1 pr-2">

      ${sections}
    </div>
  `;
}


async function loadRBACMyAccess() {
  await Promise.allSettled([loadRBACMyRoles(), loadRBACMyPermissions()]);
}

function renderPermissionList(perms) {
    if (!perms || perms.length === 0) {
        return `<div class="text-gray-500 dark:text-gray-400">No permissions found.</div>`;
    }
    const items = perms.map((p) => `<li class="py-1"><code class="text-xs">${escapeHtml(p)}</code></li>`).join("");
    return `
      <div class="max-h-72 overflow-auto border border-gray-200 dark:border-gray-700 rounded-lg p-3 bg-white dark:bg-gray-800">
        <ul class="list-disc pl-5 space-y-1">${items}</ul>
      </div>
    `;
}

async function ensureRBACRoleNameMap() {
  // if already loaded, keep it
  const map = window.__rbacState.roleNameMap || {};
  if (map && Object.keys(map).length > 0) return;

  try {
    const headers = await rbacHeaders();
    // Admin will have access. If non-admin, this may 403; then we fallback to IDs.
    const resp = await fetchWithTimeout(`${window.ROOT_PATH}/rbac/roles?active_only=false`, { headers });

    if (!resp.ok) {
      // Do not hard-fail. Just keep map empty.
      return;
    }

    const roles = await resp.json();
    const next = {};
    (roles || []).forEach((r) => {
      if (r && r.id) next[r.id] = r.name || r.id;
    });
    window.__rbacState.roleNameMap = next;
  } catch (_e) {
    // silent fallback
  }
}


function renderMyRolesTable(rows) {
  if (!rows || rows.length === 0) {
    return `<div class="text-gray-500 dark:text-gray-400">No active roles assigned.</div>`;
  }

  const roleNameMap = window.__rbacState.roleNameMap || {};

  const body = rows.map((r) => {
    const roleId = r.role_id || r.role?.id || "";
    const roleName =
      r.role_name ||
      r.role?.name ||
      roleNameMap[roleId] ||
      `Role ${shortId(roleId)}`;

    const scope = r.scope || "-";
    const scopeId = r.scope_id || "-";
    const expires = formatIsoDate(r.expires_at);

    return `
      <tr class="border-t border-gray-200 dark:border-gray-700">
        <td class="px-3 py-2">
          <div class="text-sm font-semibold text-gray-900 dark:text-gray-100">${escapeHtml(roleName)}</div>
          <div class="text-xs text-gray-500 dark:text-gray-400">${escapeHtml(roleId || "")}</div>
        </td>
        <td class="px-3 py-2 text-sm text-gray-700 dark:text-gray-300">${escapeHtml(scope)}</td>
        <td class="px-3 py-2 text-sm text-gray-700 dark:text-gray-300">${escapeHtml(scopeId)}</td>
        <td class="px-3 py-2 text-sm text-gray-600 dark:text-gray-400">${escapeHtml(expires)}</td>
      </tr>
    `;
  }).join("");

  return `
    <div class="overflow-x-auto rounded-lg ring-1 ring-gray-200 dark:ring-gray-700">
      <table class="min-w-full text-sm">
        <thead class="bg-indigo-50/60 dark:bg-indigo-900/20">
          <tr class="text-left text-gray-700 dark:text-gray-200">
            <th class="px-3 py-2 font-semibold">Role</th>
            <th class="px-3 py-2 font-semibold">Scope</th>
            <th class="px-3 py-2 font-semibold">Scope ID</th>
            <th class="px-3 py-2 font-semibold">Expires</th>
          </tr>
        </thead>
        <tbody>${body}</tbody>
      </table>
    </div>
  `;
}

/******************************************************
 * RBAC Expose to global scope (Tokens style)
 ******************************************************/
window.initializeRBACPanel = initializeRBACPanel;
window.showRBACSubTab = showRBACSubTab;

window.loadRBACRoles = loadRBACRoles;
window.filterRBACRoles = filterRBACRoles;

window.loadRBACRoleDropdown = loadRBACRoleDropdown;
window.loadRBACPermissionsDropdown = loadRBACPermissionsDropdown;

window.toggleRBACScopeId = toggleRBACScopeId;

window.loadRBACUserRoles = loadRBACUserRoles;
window.assignRBACRoleToUser = assignRBACRoleToUser;
window.revokeRBACUserRole = revokeRBACUserRole;

window.loadRBACUserPermissions = loadRBACUserPermissions;
window.checkRBACPermission = checkRBACPermission;

window.loadRBACMyAccess = loadRBACMyAccess;
window.loadRBACMyPermissions = loadRBACMyPermissions;

window.initializePermissionsPanel = initializePermissionsPanel;
window.runEffectivePermissionsAudit = runEffectivePermissionsAudit;
window.runPermissionChecksBatch = runPermissionChecksBatch;
window.clearPermissionCheckResults = clearPermissionCheckResults;

window.loadUserRoleAssignments = loadUserRoleAssignments;
window.assignRoleToSelectedUser = assignRoleToSelectedUser;
// expose to window for onclick
window.refreshRBACUserRoleAssignments = refreshRBACUserRoleAssignments;



// Debug (remove after confirm)
console.log("✅ RBAC globals ready:", {
    initializeRBACPanel: typeof window.initializeRBACPanel,
    showRBACSubTab: typeof window.showRBACSubTab,
});


// === Robust Tools toggle initializer (paste at end of admin.js) ===
(function () {
  function initToolsToggleRobust() {
    try {
      const label = document.querySelector('label[for="toggle-tools"]');
      const panel = document.querySelector('#tools-panel');
      // fallback search if structure slightly different
      const content = panel ? panel.querySelector('.content') : document.querySelector('#tools-panel .content');

      console.log('Tools toggle: init start', { labelExists: !!label, panelExists: !!panel, contentExists: !!content });

      if (!label) {
        console.warn('Tools toggle: label[for="toggle-tools"] not found — toggle disabled');
        return;
      }
      if (!content) {
        console.warn('Tools toggle: #tools-panel .content not found — toggle disabled');
        return;
      }

      // ensure we don't initialize twice
      if (label.dataset.toolsToggleInitialized === 'true') {
        console.log('Tools toggle: already initialized — skipping');
        // but update display just in case
        content.style.display = content.classList.contains('open') ? 'block' : 'none';
        return;
      }

      // If an inline onclick exists and is intended to handle toggling (user added), do not add duplicate toggle handler.
      const hasInlineOnclick = !!label.getAttribute('onclick');
      if (hasInlineOnclick) {
        console.log('Tools toggle: label has inline onclick — skipping adding extra listener. Syncing display with .open state.');
        // Make sure visual state reflects current class presence
        content.style.display = content.classList.contains('open') ? 'block' : 'none';
        label.dataset.toolsToggleInitialized = 'true';
        return;
      }

      // Set initial visibility based on .open
      const initiallyOpen = content.classList.contains('open');
      content.style.display = initiallyOpen ? 'block' : 'none';
      console.log('Tools toggle: initial open?', initiallyOpen);

      // click handler that toggles .open and display (non-destructive)
      function toggleHandler(e) {
        if (e && typeof e.preventDefault === 'function') e.preventDefault();

        const wasOpen = content.classList.contains('open');
        content.classList.toggle('open');
        const nowOpen = content.classList.contains('open');

        // Ensure display matches class
        content.style.display = nowOpen ? 'block' : 'none';

        console.log('Tools toggle: clicked — wasOpen:', wasOpen, 'nowOpen:', nowOpen);

        // focus first control when opened
        if (nowOpen) {
          const first = content.querySelector('input, textarea, select, button');
          if (first && typeof first.focus === 'function') {
            try { first.focus(); } catch (e) { /* ignore */ }
          }
        }
      }

      // Add event listeners (preserve other listeners)
      label.addEventListener('click', toggleHandler, false);
      label.addEventListener('keydown', function (e) {
        if (e.key === ' ' || e.key === 'Enter') {
          e.preventDefault();
          toggleHandler(e);
        }
      }, false);

      // mark initialized
      label.dataset.toolsToggleInitialized = 'true';
      console.log('✓ Tools toggle (robust) initialized');
    } catch (err) {
      console.error('Tools toggle init error:', err);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initToolsToggleRobust);
  } else {
    initToolsToggleRobust();
  }
})();

if (typeof testTool !== 'undefined') window.testTool = testTool;
if (typeof viewTool !== 'undefined') window.viewTool = viewTool;
if (typeof editTool !== 'undefined') window.editTool = editTool;