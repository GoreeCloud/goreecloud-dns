import i18n from './i18n';

const UPSTREAM_PRODUCT_NAME = 'AdGuard Home';
const GOREECLOUD_PRODUCT_NAME = 'GoreeCloud DNS';

type TranslationObject = Record<string, unknown>;

const replaceProductName = (value: unknown): unknown => {
    if (typeof value === 'string') {
        return value.split(UPSTREAM_PRODUCT_NAME).join(GOREECLOUD_PRODUCT_NAME);
    }

    if (Array.isArray(value)) {
        return value.map(replaceProductName);
    }

    if (value && typeof value === 'object') {
        return Object.fromEntries(
            Object.entries(value as TranslationObject).map(([key, child]) => [key, replaceProductName(child)]),
        );
    }

    return value;
};

const applyProductIdentity = () => {
    Object.keys(i18n.store.data).forEach((language) => {
        const bundle = i18n.getResourceBundle(language, 'translation') as TranslationObject | undefined;

        if (!bundle) {
            return;
        }

        i18n.addResourceBundle(language, 'translation', replaceProductName(bundle), true, true);
    });
};

if (i18n.isInitialized) {
    applyProductIdentity();
} else {
    i18n.on('initialized', applyProductIdentity);
}

export { GOREECLOUD_PRODUCT_NAME, UPSTREAM_PRODUCT_NAME, applyProductIdentity };
