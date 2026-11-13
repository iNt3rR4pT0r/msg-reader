/**
 * Regression tests for the security review findings:
 * values taken from an email file must never be interpreted as markup.
 */
import { extractEml } from '../src/js/utils.js';
import { messageToHtmlDocument } from '../src/js/messageExport.js';
import { MessageContentRenderer } from '../src/js/ui/MessageContentRenderer.js';
import { MessageListRenderer } from '../src/js/ui/MessageListRenderer.js';
import { AttachmentModalManager } from '../src/js/ui/AttachmentModalManager.js';

function toArrayBuffer(text) {
    const bytes = Buffer.from(text, 'latin1');
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function parse(eml) {
    const info = extractEml(toArrayBuffer(eml));
    info.timestamp = new Date('2024-06-15T10:30:00Z');
    return info;
}

function createModalStub() {
    return {
        isPreviewable: () => true,
        isPreviewableImage: (mime) => (mime || '').startsWith('image/'),
        isPdf: () => false,
        isText: () => false,
        isPreviewableEml: () => false,
        setAttachments: () => {}
    };
}

function renderMessage(info) {
    document.body.innerHTML = '<div id="viewer"></div>';
    const container = document.getElementById('viewer');
    const handler = {
        setCurrentMessage: () => {},
        getMessages: () => [info],
        isPinned: () => false
    };
    new MessageContentRenderer(container, handler, createModalStub()).render(info);
    return container;
}

function expectNoActiveContent(root) {
    expect(root.querySelector('script')).toBeNull();
    root.querySelectorAll('*').forEach((element) => {
        Array.from(element.attributes).forEach((attribute) => {
            expect(attribute.name.toLowerCase().startsWith('on')).toBe(false);
        });
    });
}

const PAYLOAD = '<img src=x onerror=alert(1)>';

const MALICIOUS_EML = [
    `From: ${PAYLOAD} <attacker@example.com>`,
    'To: victim@example.com',
    `Subject: ${PAYLOAD}`,
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="B"',
    '',
    '--B',
    'Content-Type: text/html',
    '',
    '<p>hello</p><script>alert(1)</script><img src="https://tracker.example/p.gif">',
    '--B',
    `Content-Type: application/${PAYLOAD}`,
    'Content-Disposition: attachment; filename="a.bin"',
    'Content-Transfer-Encoding: base64',
    '',
    'QUFB',
    '--B',
    'Content-Type: image/png" onerror="alert(1)',
    'Content-Disposition: attachment; filename="b.png"',
    'Content-Transfer-Encoding: base64',
    '',
    'QUFB"onerror="alert(1)',
    '--B--',
    ''
].join('\r\n');

describe('untrusted email fields', () => {
    test('attachment MIME types and content are normalized while parsing', () => {
        const info = parse(MALICIOUS_EML);
        expect(info.attachments).toHaveLength(2);
        info.attachments.forEach((attachment) => {
            expect(attachment.attachMimeTag).toMatch(/^[a-z0-9.+-]+\/[a-z0-9.+-]+$/);
            expect(attachment.contentBase64).toMatch(/^data:[a-z0-9.+/-]+;base64,[A-Za-z0-9+/=]*$/);
        });
    });

    test('message view renders subject and attachment metadata as text', () => {
        const container = renderMessage(parse(MALICIOUS_EML));

        expectNoActiveContent(container);
        expect(container.querySelector('.message-title img')).toBeNull();
        expect(container.querySelector('.message-title').textContent).toBe(PAYLOAD);
        expect(container.querySelector('.attachment-meta img')).toBeNull();
        expect(container.innerHTML).not.toContain('tracker.example');
    });

    test('message list renders sender, subject and preview as text', () => {
        const info = parse(MALICIOUS_EML);
        info.senderName = PAYLOAD;
        info.bodyContent = '<img src=x onerror=alert(1) ';

        const html = MessageListRenderer.prototype.renderMessageItem.call(
            {
                messageHandler: {
                    getCurrentMessage: () => null,
                    getMessages: () => [info],
                    isPinned: () => false,
                    isSelected: () => false
                },
                filteredMessages: null,
                selectionMode: false,
                formatMessageDate: () => 'today'
            },
            info,
            0
        );

        const root = document.createElement('div');
        root.innerHTML = html;
        expectNoActiveContent(root);
        expect(root.querySelector('img')).toBeNull();
        expect(root.querySelector('.message-subject').textContent).toBe(PAYLOAD);
        expect(root.querySelector('.message-sender').textContent).toBe(PAYLOAD);
    });

    test('HTML export does not carry scripts or remote content', () => {
        const html = messageToHtmlDocument(parse(MALICIOUS_EML));
        const start = html.indexOf('<section class="content">');
        const end = html.indexOf('</section>', start);
        const body = html.slice(start, end);

        expect(html).toContain('Content-Security-Policy');
        expect(body).not.toMatch(/<script/i);
        expect(body).not.toContain('tracker.example');
        expect(html).not.toMatch(/<h1><img/i);
    });

    test('nested email preview is sanitized and fully sandboxed', () => {
        document.body.innerHTML = `
            <div id="attachmentModal">
                <span id="attachmentModalFilename"></span>
                <div id="attachmentModalContent"></div>
            </div>`;
        const modal = new AttachmentModalManager(() => {});
        modal.attachmentModalContent = document.getElementById('attachmentModalContent');

        const dataUrl = `data:message/rfc822;base64,${Buffer.from(MALICIOUS_EML, 'latin1').toString('base64')}`;
        modal.renderNestedEmailPreview({
            fileName: 'nested.eml',
            attachMimeTag: 'message/rfc822',
            contentBase64: dataUrl
        });

        const content = document.getElementById('attachmentModalContent');
        const iframe = content.querySelector('iframe');
        expect(iframe).not.toBeNull();
        expect(iframe.getAttribute('sandbox')).toBe('');
        expect(iframe.srcdoc).not.toMatch(/<script/i);
        expect(iframe.srcdoc).not.toContain('tracker.example');
        expectNoActiveContent(content);
        expect(content.querySelector('.nested-email-header img')).toBeNull();
        expect(content.querySelector('.attachment-meta img')).toBeNull();
    });
});
