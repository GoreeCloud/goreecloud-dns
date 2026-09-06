import { test, expect } from '@playwright/test';
import { ADMIN_USERNAME, ADMIN_PASSWORD } from '../constants';

test.describe('Control Panel', () => {
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

    test('should expose Beacon Insights as an aggregate-first DNS overview', async ({ page }) => {
        await expect(page.getByRole('heading', { name: 'Beacon Insights' })).toBeVisible();
        await expect(page.getByRole('heading', { name: 'DNS Resolution Path' })).toBeVisible();
        await expect(page.getByText('Aggregate by default')).toBeVisible();
        await expect(page.getByTestId('beacon-query-total')).toBeVisible();
        await expect(page.getByTestId('beacon-filtered-total')).toBeVisible();
        await expect(page.getByTestId('beacon-client-total')).toBeVisible();
        await expect(page.getByTestId('beacon-upstream-total')).toBeVisible();
        await expect(page.getByTestId('beacon-latency')).toBeVisible();
        await expect(page.getByRole('link', { name: 'Open Query Log' })).toBeVisible();
        await expect(page.getByRole('link', { name: 'Manage Clients' })).toBeVisible();
        await expect(page.getByRole('link', { name: 'DNS Settings' })).toBeVisible();
        await expect(page.getByRole('link', { name: 'Filter Lists' })).toBeVisible();
    });

    test('should keep Beacon Insights reachable without horizontal overflow on compact screens', async ({ page }) => {
        await page.setViewportSize({ width: 390, height: 844 });

        await expect(page.getByRole('heading', { name: 'Beacon Insights' })).toBeVisible();
        await expect(page.getByTestId('beacon-query-total')).toBeVisible();

        const hasHorizontalOverflow = await page.evaluate(
            () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
        );
        expect(hasHorizontalOverflow).toBeFalsy();
    });

    test('should expose mobile navigation state and controlled landmark', async ({ page }) => {
        await page.setViewportSize({ width: 390, height: 844 });

        const navigationToggle = page.getByRole('button', { name: 'GoreeCloud DNS navigation' });
        const navigation = page.locator('#goreecloud-primary-navigation');

        await expect(navigationToggle).toHaveAttribute('aria-controls', 'goreecloud-primary-navigation');
        await expect(navigationToggle).toHaveAttribute('aria-expanded', 'false');
        await expect(navigation).toHaveAttribute('aria-label', 'GoreeCloud DNS navigation');

        await navigationToggle.click();
        await expect(navigationToggle).toHaveAttribute('aria-expanded', 'true');

        await navigationToggle.click();
        await expect(navigationToggle).toHaveAttribute('aria-expanded', 'false');
    });

    test('should sign out successfully', async ({ page }) => {
        await page.getByTestId('sign_out').click();

        await page.waitForURL((url) => url.href.endsWith('/login.html'));

        await expect(page.getByTestId('sign_in')).toBeVisible();
    });

    test('should change theme to dark and then light', async ({ page }) => {
        await page.getByTestId('theme_dark').click();

        await expect(page.locator('body[data-theme="dark"]')).toBeVisible();

        await page.getByTestId('theme_light').click();

        await expect(page.locator('body:not([data-theme="dark"])')).toBeVisible();
    });
});
