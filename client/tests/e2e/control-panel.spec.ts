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
