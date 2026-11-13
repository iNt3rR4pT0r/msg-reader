/**
 * Tests for sanitizer.js
 * Ensures XSS protection and HTML sanitization work correctly
 */
import {
    sanitizeHTML,
    escapeHTML,
    sanitizeURL,
    sanitizeMimeType,
    stripRemoteCss,
    SANITIZE_CONFIG
} from '../src/js/sanitizer.js';

describe('SANITIZE_CONFIG', () => {
    test('has required allowed tags', () => {
        expect(SANITIZE_CONFIG.ALLOWED_TAGS).toContain('p');
        expect(SANITIZE_CONFIG.ALLOWED_TAGS).toContain('div');
        expect(SANITIZE_CONFIG.ALLOWED_TAGS).toContain('a');
        expect(SANITIZE_CONFIG.ALLOWED_TAGS).toContain('img');
        expect(SANITIZE_CONFIG.ALLOWED_TAGS).toContain('table');
    });

    test('forbids dangerous tags', () => {
        expect(SANITIZE_CONFIG.FORBID_TAGS).toContain('script');
        expect(SANITIZE_CONFIG.FORBID_TAGS).toContain('iframe');
        expect(SANITIZE_CONFIG.FORBID_TAGS).toContain('form');
        expect(SANITIZE_CONFIG.FORBID_TAGS).toContain('input');
    });

    test('forbids event handler attributes', () => {
        expect(SANITIZE_CONFIG.FORBID_ATTR).toContain('onclick');
        expect(SANITIZE_CONFIG.FORBID_ATTR).toContain('onerror');
        expect(SANITIZE_CONFIG.FORBID_ATTR).toContain('onload');
        expect(SANITIZE_CONFIG.FORBID_ATTR).toContain('onmouseover');
    });
});

describe('sanitizeHTML', () => {
    test('removes script tags', () => {
        const input = '<p>Hello</p><script>alert("xss")</script>';
        const result = sanitizeHTML(input);
        expect(result).not.toContain('<script');
        expect(result).not.toContain('alert');
        expect(result).toContain('<p>Hello</p>');
    });

    test('removes onclick handlers', () => {
        const input = '<div onclick="alert(1)">Click</div>';
        const result = sanitizeHTML(input);
        expect(result).not.toContain('onclick');
        expect(result).toContain('Click');
    });

    test('removes onerror handlers', () => {
        const input = '<img src="x" onerror="alert(1)">';
        const result = sanitizeHTML(input);
        expect(result).not.toContain('onerror');
    });

    test('preserves safe tags', () => {
        const input = '<p>Hello <strong>world</strong></p>';
        const result = sanitizeHTML(input);
        expect(result).toContain('<p>');
        expect(result).toContain('<strong>');
        expect(result).toContain('world');
    });

    test('preserves links with href', () => {
        const input = '<a href="https://example.com">Link</a>';
        const result = sanitizeHTML(input);
        expect(result).toContain('href="https://example.com"');
        expect(result).toContain('Link');
    });

    test('preserves embedded images', () => {
        const input = '<img src="data:image/png;base64,AAAA" alt="Test">';
        const result = sanitizeHTML(input);
        expect(result).toContain('src="data:image/png;base64,AAAA"');
        expect(result).toContain('alt="Test"');
    });

    test('blocks remote images (tracking pixels)', () => {
        const result = sanitizeHTML('<img src="https://example.com/pixel.gif" alt="Test">');
        expect(result).not.toContain('example.com');
        expect(result).toContain('alt="Test"');
    });

    test('labels blocked images without alt text', () => {
        const result = sanitizeHTML('<p>x</p><img src="//example.com/pixel.gif">');
        expect(result).not.toContain('example.com');
        expect(result).toContain('[external image blocked]');
    });

    test('removes remote references from style attributes', () => {
        const result = sanitizeHTML(
            '<div style="color: red; background: url(https://example.com/bg.png)">x</div>'
        );
        expect(result).not.toContain('example.com');
        expect(result).toContain('color: red');
    });

    test('removes escaped url() from style attributes', () => {
        // Hex escapes lose their meaning (the declaration becomes invalid CSS)...
        const hexEscaped = sanitizeHTML(
            '<div style="background: u\\72l(https://example.com/bg.png)">x</div>'
        );
        expect(hexEscaped).not.toContain('\\');
        expect(hexEscaped).not.toMatch(/url\s*\(/i);

        // ...and literal escapes collapse into a plain url() that is removed.
        const literalEscaped = sanitizeHTML(
            '<div style="background: \\u\\r\\l(https://example.com/bg.png)">x</div>'
        );
        expect(literalEscaped).not.toContain('example.com');
    });

    test('removes remote references from style blocks', () => {
        const result = sanitizeHTML(
            '<p>x</p><style>@import url(https://example.com/a.css); p { background: url("https://example.com/b.png"); color: blue; }</style>'
        );
        expect(result).not.toContain('example.com');
        expect(result).not.toContain('@import');
        expect(result).toContain('color: blue');
    });

    test('forces links into a new context', () => {
        const result = sanitizeHTML('<a href="https://example.com/">link</a>');
        expect(result).toContain('href="https://example.com/"');
        expect(result).toContain('target="_blank"');
        expect(result).toContain('rel="noopener noreferrer"');
    });

    test('drops link targets with unexpected schemes', () => {
        const result = sanitizeHTML(
            '<a href="file:///etc/passwd">a</a><a href="data:text/html,x">b</a><a href="ms-msdt:/id">c</a>'
        );
        expect(result).not.toContain('href');
    });

    test('preserves table structure', () => {
        const input = '<table><tr><td>Cell</td></tr></table>';
        const result = sanitizeHTML(input);
        expect(result).toContain('<table>');
        expect(result).toContain('<tr>');
        expect(result).toContain('<td>');
        expect(result).toContain('Cell');
    });

    test('removes iframe tags', () => {
        const input = '<iframe src="https://evil.com"></iframe>';
        const result = sanitizeHTML(input);
        expect(result).not.toContain('<iframe');
    });

    test('removes form elements', () => {
        const input = '<form action="/"><input type="text"><button>Submit</button></form>';
        const result = sanitizeHTML(input);
        expect(result).not.toContain('<form');
        expect(result).not.toContain('<input');
        expect(result).not.toContain('<button');
    });

    test('handles empty input', () => {
        expect(sanitizeHTML('')).toBe('');
        expect(sanitizeHTML(null)).toBe('');
        expect(sanitizeHTML(undefined)).toBe('');
    });

    test('handles style tags consistently', () => {
        const input = '<style>.test { color: red; }</style><div class="test">Styled</div>';
        const result = sanitizeHTML(input);
        // DOMPurify may remove style tags in JSDOM environment
        // The important thing is that it doesn't throw and preserves the div
        expect(result).toContain('Styled');
        expect(result).toContain('class="test"');
    });

    test('preserves legacy font tags', () => {
        const input = '<font color="red">Red text</font>';
        const result = sanitizeHTML(input);
        expect(result).toContain('<font');
        expect(result).toContain('color="red"');
    });
});

describe('escapeHTML', () => {
    test('escapes HTML special characters', () => {
        const input = '<script>alert("xss")</script>';
        const result = escapeHTML(input);
        expect(result).toContain('&lt;');
        expect(result).toContain('&gt;');
        expect(result).not.toContain('<script>');
    });

    test('escapes ampersands', () => {
        const input = 'Hello & World';
        const result = escapeHTML(input);
        expect(result).toContain('&amp;');
    });

    test('escapes quotes so the result is safe inside attributes', () => {
        expect(escapeHTML('Say "Hello"')).toBe('Say &quot;Hello&quot;');
        expect(escapeHTML("it's")).toBe('it&#39;s');
        expect(escapeHTML('x" onerror="alert(1)')).not.toContain('"');
    });

    test('stringifies non-string values', () => {
        expect(escapeHTML(42)).toBe('42');
        expect(escapeHTML(0)).toBe('0');
    });

    test('handles empty input', () => {
        expect(escapeHTML('')).toBe('');
        expect(escapeHTML(null)).toBe('');
        expect(escapeHTML(undefined)).toBe('');
    });

    test('preserves normal text', () => {
        const input = 'Hello World';
        const result = escapeHTML(input);
        expect(result).toBe('Hello World');
    });
});

describe('sanitizeURL', () => {
    test('allows https URLs', () => {
        const url = 'https://example.com/path?query=1';
        expect(sanitizeURL(url)).toBe(url);
    });

    test('allows http URLs', () => {
        const url = 'http://example.com/path';
        expect(sanitizeURL(url)).toBe(url);
    });

    test('allows mailto URLs', () => {
        const url = 'mailto:test@example.com';
        expect(sanitizeURL(url)).toBe(url);
    });

    test('allows data:image URLs', () => {
        const url = 'data:image/png;base64,ABC123';
        expect(sanitizeURL(url)).toBe(url);
    });

    test('allows data:image/jpeg URLs', () => {
        const url = 'data:image/jpeg;base64,/9j/4AAQ';
        expect(sanitizeURL(url)).toBe(url);
    });

    test('blocks javascript URLs', () => {
        expect(sanitizeURL('javascript:alert(1)')).toBe('');
        expect(sanitizeURL('JAVASCRIPT:alert(1)')).toBe('');
        expect(sanitizeURL('  javascript:alert(1)  ')).toBe('');
    });

    test('blocks data:text/html URLs', () => {
        expect(sanitizeURL('data:text/html,<script>alert(1)</script>')).toBe('');
    });

    test('blocks data:application URLs', () => {
        expect(sanitizeURL('data:application/javascript,alert(1)')).toBe('');
    });

    test('blocks vbscript URLs', () => {
        expect(sanitizeURL('vbscript:msgbox("xss")')).toBe('');
    });

    test('handles empty input', () => {
        expect(sanitizeURL('')).toBe('');
        expect(sanitizeURL(null)).toBe('');
        expect(sanitizeURL(undefined)).toBe('');
    });

    test('handles URLs with whitespace', () => {
        const url = '  https://example.com  ';
        expect(sanitizeURL(url)).toBe(url);
    });
});

describe('sanitizeMimeType', () => {
    test('keeps well-formed MIME types', () => {
        expect(sanitizeMimeType('image/png')).toBe('image/png');
        expect(sanitizeMimeType('Application/PDF')).toBe('application/pdf');
        expect(sanitizeMimeType('image/svg+xml')).toBe('image/svg+xml');
        expect(sanitizeMimeType('application/vnd.ms-outlook')).toBe('application/vnd.ms-outlook');
        expect(sanitizeMimeType('text/plain; charset=utf-8')).toBe('text/plain');
    });

    test('rejects markup and attribute breakouts', () => {
        expect(sanitizeMimeType('application/<img src=x onerror=alert(1)>')).toBe(
            'application/octet-stream'
        );
        expect(sanitizeMimeType('image/x" onerror="alert(1)')).toBe('application/octet-stream');
        expect(sanitizeMimeType('')).toBe('application/octet-stream');
        expect(sanitizeMimeType(undefined)).toBe('application/octet-stream');
    });
});

describe('stripRemoteCss', () => {
    test('keeps embedded images', () => {
        expect(stripRemoteCss('background: url(data:image/png;base64,AAAA)')).toContain(
            'url(data:image/png;base64,AAAA)'
        );
    });

    test('removes remote urls, imports and image-set', () => {
        const css =
            '@import "https://a.example/x.css"; a { background: url( \'https://a.example/y\' ); b: image-set("https://a.example/z" 1x); }';
        const result = stripRemoteCss(css);
        expect(result).not.toContain('a.example');
    });

    test('is not fooled by comments inside keywords', () => {
        expect(stripRemoteCss('background: u/**/rl(https://a.example/y)')).not.toContain('url(');
    });

    test('handles empty input', () => {
        expect(stripRemoteCss('')).toBe('');
        expect(stripRemoteCss(null)).toBe('');
    });
});
