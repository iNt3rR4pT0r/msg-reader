/**
 * HTML Sanitization Module
 * Protects against XSS attacks by sanitizing untrusted HTML content
 */
import DOMPurify from 'dompurify';

/**
 * Configuration for DOMPurify
 * Allows common email HTML elements while blocking dangerous ones
 */
export const SANITIZE_CONFIG = {
    ALLOWED_TAGS: [
        // Text formatting
        'p', 'br', 'div', 'span', 'b', 'i', 'u', 'strong', 'em', 'mark', 'small', 'del', 'ins', 'sub', 'sup',
        // Headings
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        // Lists
        'ul', 'ol', 'li', 'dl', 'dt', 'dd',
        // Tables
        'table', 'tr', 'td', 'th', 'thead', 'tbody', 'tfoot', 'caption', 'colgroup', 'col',
        // Links and media
        'a', 'img',
        // Structure
        'blockquote', 'pre', 'code', 'hr', 'address',
        // Styling (scoped in email context)
        'style',
        // Font tags (legacy emails)
        'font', 'center'
    ],
    ALLOWED_ATTR: [
        // Common
        'class', 'id', 'style', 'title',
        // Links
        'href', 'target', 'rel',
        // Images
        'src', 'alt', 'width', 'height',
        // Tables
        'colspan', 'rowspan', 'cellpadding', 'cellspacing', 'border', 'align', 'valign', 'bgcolor',
        // Font (legacy)
        'color', 'face', 'size'
    ],
    ALLOW_DATA_ATTR: false,
    FORBID_TAGS: ['script', 'iframe', 'object', 'embed', 'form', 'input', 'button', 'select', 'textarea', 'applet', 'base', 'meta', 'link'],
    FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'onmouseout', 'onfocus', 'onblur', 'onchange', 'onsubmit', 'onkeydown', 'onkeyup', 'onkeypress'],
    // Allow data: URLs only for images (base64 embedded images are common in emails)
    ALLOW_UNKNOWN_PROTOCOLS: false,
    ADD_ATTR: ['target'],
    // Force all links to open in new tab for security
    WHOLE_DOCUMENT: false,
    RETURN_DOM: false,
    RETURN_DOM_FRAGMENT: false
};

/**
 * Image sources that never trigger a network request.
 * Remote images are blocked: they are used as tracking pixels and leak the
 * reader's IP address as soon as a message is opened.
 */
const LOCAL_IMAGE_SRC = /^\s*(?:data:image\/|blob:)/i;

/** Link targets that are safe to keep clickable. */
const SAFE_LINK_HREF = /^\s*(?:https?:|mailto:|tel:|#)/i;

const BLOCKED_IMAGE_ALT = '[external image blocked]';

/**
 * Removes everything from a CSS string that can trigger a network request
 * (url(), image-set(), @import, ...). Only embedded data:image URLs survive.
 * Backslashes are dropped first because CSS escapes (u\72l(...)) would
 * otherwise hide a url() from the checks below.
 * @param {string} css - Untrusted CSS (style attribute value or stylesheet)
 * @returns {string} CSS without remote references
 */
export function stripRemoteCss(css) {
    if (!css) return '';

    return (
        String(css)
            .replace(/\\/g, '')
            // HTML comment tokens and CSS comments can split keywords
            .replace(/<!--|-->/g, '')
            .replace(/\/\*[\s\S]*?(?:\*\/|$)/g, '')
            // @import with or without url()
            .replace(/@import\b[^;{}]*;?/gi, '')
            // url(...) unless it is an embedded image
            .replace(/url\s*\(\s*(['"]?)\s*(?!data:image\/)[^)]*\)?/gi, 'none')
            // functions that accept bare strings as URLs
            .replace(/(?:-webkit-)?(?:image-set|cross-fade|image|src)\s*\([^;{}]*/gi, 'none')
            // legacy script-capable CSS
            .replace(/expression\s*\(|behavior\s*:|-moz-binding\s*:/gi, 'blocked:')
    );
}

let hooksInstalled = false;

/**
 * Installs the DOMPurify hooks that enforce the "no remote content" policy.
 * Hooks are global for the DOMPurify instance, so this runs only once.
 */
function installHooks() {
    if (hooksInstalled || typeof DOMPurify.addHook !== 'function') return;
    hooksInstalled = true;

    DOMPurify.addHook('uponSanitizeElement', (node, data) => {
        if (data.tagName === 'style' && node.textContent) {
            node.textContent = stripRemoteCss(node.textContent);
        }
    });

    DOMPurify.addHook('afterSanitizeAttributes', (node) => {
        if (!node || typeof node.getAttribute !== 'function') return;

        if (node.hasAttribute('style')) {
            const cleaned = stripRemoteCss(node.getAttribute('style'));
            if (cleaned.trim()) {
                node.setAttribute('style', cleaned);
            } else {
                node.removeAttribute('style');
            }
        }

        const tagName = (node.nodeName || '').toLowerCase();

        if (tagName === 'img' && node.hasAttribute('src')) {
            if (!LOCAL_IMAGE_SRC.test(node.getAttribute('src'))) {
                node.removeAttribute('src');
                if (!node.getAttribute('alt')) {
                    node.setAttribute('alt', BLOCKED_IMAGE_ALT);
                }
            }
        }

        if (tagName === 'a' && node.hasAttribute('href')) {
            if (SAFE_LINK_HREF.test(node.getAttribute('href'))) {
                // Never let a link replace the app itself or reach back into it
                node.setAttribute('target', '_blank');
                node.setAttribute('rel', 'noopener noreferrer');
            } else {
                node.removeAttribute('href');
                node.removeAttribute('target');
            }
        }
    });
}

/**
 * Removes problematic MS Office CSS properties that break layout in browsers
 * @param {string} html - HTML content with style attributes
 * @returns {string} HTML with cleaned style attributes
 */
function cleanMsoStyles(html) {
    if (!html) return '';

    // Clean style attributes in the HTML
    return html.replace(/style="([^"]*)"/gi, (match, styleValue) => {
        const cleaned = styleValue
            // Remove absolute/fixed positioning (breaks layout outside Outlook)
            .replace(/position\s*:\s*(absolute|fixed)[^;]*/gi, '')
            // Remove MSO-specific positioning properties only
            .replace(/mso-position[^:]*:[^;]+;?/gi, '')
            // Clean up multiple semicolons and whitespace
            .replace(/;\s*;/g, ';')
            .replace(/^\s*;\s*/g, '')
            .trim();

        return cleaned ? `style="${cleaned}"` : '';
    });
}

/**
 * Sanitizes HTML content to prevent XSS attacks
 * @param {string} html - The untrusted HTML content
 * @returns {string} Sanitized HTML safe for innerHTML
 */
export function sanitizeHTML(html) {
    if (!html) return '';

    // Clean problematic MSO styles before sanitizing
    const cleanedHtml = cleanMsoStyles(html);

    let cleanHTML;
    try {
        installHooks();
        cleanHTML = DOMPurify.sanitize(cleanedHtml, SANITIZE_CONFIG);
    } catch (error) {
        console.error('Error sanitizing HTML:', error);
        // Return escaped text as fallback
        return escapeHTML(html);
    }

    return cleanHTML;
}

/**
 * Escapes HTML special characters
 * @param {string} text - Plain text to escape
 * @returns {string} HTML-escaped text
 */
export function escapeHTML(text) {
    if (text === null || text === undefined || text === '') return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

const SAFE_MIME_TYPE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$/;

/**
 * Normalizes an untrusted MIME type. Anything that is not a plain
 * "type/subtype" token falls back to application/octet-stream, so the value
 * can be used in data: URLs and shown in the UI.
 * @param {string} mimeType - MIME type taken from the email file
 * @returns {string} Safe, lower-case MIME type
 */
export function sanitizeMimeType(mimeType) {
    const normalized = String(mimeType || '')
        .split(';')[0]
        .trim()
        .toLowerCase();
    return SAFE_MIME_TYPE.test(normalized) ? normalized : 'application/octet-stream';
}

/**
 * Sanitizes a URL to prevent javascript: and data: URL attacks
 * Allows http:, https:, mailto:, and data:image for embedded images
 * @param {string} url - The URL to sanitize
 * @returns {string} Safe URL or empty string if dangerous
 */
export function sanitizeURL(url) {
    if (!url) return '';

    const trimmed = url.trim().toLowerCase();

    // Allow safe protocols
    if (trimmed.startsWith('http://') ||
        trimmed.startsWith('https://') ||
        trimmed.startsWith('mailto:')) {
        return url;
    }

    // Allow data:image URLs (common in emails for embedded images)
    if (trimmed.startsWith('data:image/')) {
        return url;
    }

    // Block everything else (javascript:, data:text/html, etc.)
    return '';
}
