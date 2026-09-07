import { test, expect } from '@playwright/test';
import { ADMIN_PASSWORD, ADMIN_USERNAME } from '../constants';

const emptyTlsStatus = {
    enabled: false,
    serve_plain_dns: true,
    server_name: '',
    force_https: false,
    port_https: 443,
    port_dns_over_tls: 853,
    port_dns_over_quic: 853,
    certificate_chain: '',
    private_key: '',
    certificate_path: '',
    private_key_path: '',
    private_key_saved: false,
    valid_chain: false,
    valid_key: false,
    valid_cert: false,
    valid_pair: false,
    dns_names: [],
    key_type: '',
    issuer: '',
    subject: '',
    not_after: '',
    not_before: '',
    warning_validation: '',
};

const validatedTlsStatus = {
    ...emptyTlsStatus,
    enabled: true,
    certificate_path: '/tmp/goreecloud-dns-test.crt',
    private_key_path: '/tmp/goreecloud-dns-test.key',
    valid_chain: true,
    valid_key: true,
    valid_cert: true,
    valid_pair: true,
    key_type: 'RSA',
};

test.describe('Encryption', () => {
    test.beforeEach(async ({ page }) => {
        await page.route('/control/tls/status', async (route) => {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify(emptyTlsStatus),
            });
        });

        await page.route('/control/tls/validate', async (route) => {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify(validatedTlsStatus),
            });
        });

        await page.goto('/login.html');
        await page.getByTestId('username').fill(ADMIN_USERNAME);
        await page.getByTestId('password').fill(ADMIN_PASSWORD);
        await page.getByTestId('sign_in').click();
        await page.waitForURL((url) => !url.href.endsWith('/login.html'));
        await page.goto('/#encryption');
    });

    test('should expose certificate and private-key validation results as polite status regions', async ({ page }) => {
        const enabled = page.locator('input[name="enabled"]');
        await enabled.check();

        const certificatePath = page.locator('input[name="certificate_path"]');
        await certificatePath.fill('/tmp/goreecloud-dns-test.crt');
        await certificatePath.blur();

        const privateKeyPath = page.locator('input[name="private_key_path"]');
        await privateKeyPath.fill('/tmp/goreecloud-dns-test.key');
        await privateKeyPath.blur();

        await expect.poll(async () => page.getByRole('status').count()).toBe(2);

        const statusRegions = page.getByRole('status');
        await expect(statusRegions.nth(0)).toHaveAttribute('aria-live', 'polite');
        await expect(statusRegions.nth(1)).toHaveAttribute('aria-live', 'polite');
        await expect(statusRegions.nth(0)).not.toHaveText('');
        await expect(statusRegions.nth(1)).not.toHaveText('');
    });
});
