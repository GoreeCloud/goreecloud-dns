import { test, expect } from '@playwright/test';
import { ADMIN_USERNAME, ADMIN_PASSWORD } from '../constants';

test.describe('QueryLog', () => {
    test.beforeEach(async ({ page }) => {
        await page.goto('/login.html');
        await page.getByTestId('username').click();
        await page.getByTestId('username').fill(ADMIN_USERNAME);
        await page.getByTestId('password').click();
        await page.getByTestId('password').fill(ADMIN_PASSWORD);
        await page.keyboard.press('Tab');
        await page.getByTestId('sign_in').click();
        await page.waitForURL((url) => !url.href.endsWith('/login.html'));
    });

    test('should expose accessible search guidance and keyboard clear control', async ({ page }) => {
        await page.goto('/#logs');

        const searchForm = page.locator('form[role="search"]');
        const searchInput = page.getByTestId('querylog_search');

        await expect(searchForm).toBeVisible();
        await expect(searchInput).toHaveAttribute('id', 'querylog_search');
        await expect(searchInput).toHaveAttribute('aria-describedby', /querylog_search-help/);
        await expect(page.locator('#querylog_search-help')).toHaveCount(1);

        await searchInput.fill('example.org');

        const clearButton = searchForm.locator('button[type="button"]');
        await expect(clearButton).toBeVisible();
        await expect(clearButton).toHaveAttribute('aria-label', /.+/);

        await clearButton.focus();
        await page.keyboard.press('Enter');
        await expect(searchInput).toHaveValue('');
    });

    test('Search of queryLog should work correctly', async ({ page }) => {
        await page.route('/control/querylog', async (route) => {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({
                    data: [
                        {
                            answer: [
                                {
                                    type: 'A',
                                    value: '77.88.44.242',
                                    ttl: 294,
                                },
                                {
                                    type: 'A',
                                    value: '5.255.255.242',
                                    ttl: 294,
                                },
                                {
                                    type: 'A',
                                    value: '77.88.55.242',
                                    ttl: 294,
                                },
                            ],
                            answer_dnssec: false,
                            cached: false,
                            client: '127.0.0.1',
                            client_info: {
                                whois: {},
                                name: 'localhost',
                                disallowed_rule: '127.0.0.1',
                                disallowed: false,
                            },
                            client_proto: '',
                            elapsedMs: '78.163167',
                            question: {
                                class: 'IN',
                                name: 'ya.ru',
                                type: 'A',
                            },
                            reason: 'NotFilteredNotFound',
                            rules: [],
                            status: 'NOERROR',
                            time: '2024-07-17T16:02:37.500662+02:00',
                            upstream: 'https://dns10.quad9.net:443/dns-query',
                        },
                        {
                            answer: [
                                {
                                    type: 'A',
                                    value: '77.88.55.242',
                                    ttl: 351,
                                },
                                {
                                    type: 'A',
                                    value: '77.88.44.242',
                                    ttl: 351,
                                },
                                {
                                    type: 'A',
                                    value: '5.255.255.242',
                                    ttl: 351,
                                },
                            ],
                            answer_dnssec: false,
                            cached: false,
                            client: '127.0.0.1',
                            client_info: {
                                whois: {},
                                name: 'localhost',
                                disallowed_rule: '127.0.0.1',
                                disallowed: false,
                            },
                            client_proto: '',
                            elapsedMs: '5051.070708',
                            question: {
                                class: 'IN',
                                name: 'ya.ru',
                                type: 'A',
                            },
                            reason: 'NotFilteredNotFound',
                            rules: [],
                            status: 'NOERROR',
                            time: '2024-07-17T16:02:37.4983+02:00',
                            upstream: 'https://dns10.quad9.net:443/dns-query',
                        },
                    ],
                    oldest: '2024-07-17T16:02:37.4983+02:00',
                }),
            });
        });

        await page.goto('/#logs');

        await page.getByTestId('querylog_search').fill('127.0.0.1');

        const [request] = await Promise.all([
            page.waitForRequest((req) => req.url().includes('/control/querylog')),
        ]);

        if (request) {
            expect(request.url()).toContain('search=127.0.0.1');
            expect(await page.getByTestId('querylog_cell').first().isVisible()).toBe(true);
        }
    });
});
