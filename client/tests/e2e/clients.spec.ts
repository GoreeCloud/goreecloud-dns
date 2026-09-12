import { test, expect } from '@playwright/test';
import { ADMIN_PASSWORD, ADMIN_USERNAME } from '../constants';

test.describe('Clients', () => {
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

    test('should associate the add-client dialog with its visible title', async ({ page }) => {
        await page.goto('/#clients?clientId=192.0.2.10');

        const dialog = page.getByRole('dialog');
        await expect(dialog).toBeVisible();
        await expect(dialog).toHaveAttribute('aria-labelledby', 'client-modal-title');

        const title = page.locator('#client-modal-title');
        await expect(title).toBeVisible();
        await expect(title).not.toHaveText('');
    });
});
