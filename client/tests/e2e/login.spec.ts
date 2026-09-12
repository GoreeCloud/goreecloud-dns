import { expect, test } from '@playwright/test';
import { ADMIN_PASSWORD, ADMIN_USERNAME } from '../constants';


test.describe('Login', () => {
    test('should expose forgot-password disclosure state and controlled help', async ({ page }) => {
        await page.goto('/login.html');

        const disclosure = page.getByRole('button', { name: /forgot/i });
        await expect(disclosure).toHaveAttribute('aria-expanded', 'false');
        await expect(disclosure).toHaveAttribute('aria-controls', 'forgot-password-help');
        await expect(page.locator('#forgot-password-help')).toHaveCount(0);

        await disclosure.click();

        await expect(disclosure).toHaveAttribute('aria-expanded', 'true');
        await expect(page.locator('#forgot-password-help')).toBeVisible();
    });

    test('should successfully log in with valid credentials', async ({ page }) => {
        await page.goto('/login.html');
        await page.getByTestId('username').click();
        await page.getByTestId('username').fill(ADMIN_USERNAME);
        await page.getByTestId('password').click();
        await page.getByTestId('password').fill(ADMIN_PASSWORD);
        await page.keyboard.press('Tab');
        await page.getByTestId('sign_in').click();
        await page.waitForURL((url) => !url.href.endsWith('/login.html'));
    });
});
