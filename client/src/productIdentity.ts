import i18n from './i18n';

const UPSTREAM_PRODUCT_NAME = 'AdGuard Home';
const GOREECLOUD_PRODUCT_NAME = 'GoreeCloud DNS';

type TranslationValue =
    | string
    | number
    | boolean
    | null
    | TranslationValue[]
    | { [key: string]: TranslationValue };
type TranslationObject = { [key: string]: TranslationValue };

const replaceProductName = (value: TranslationValue): TranslationValue => {
    if (typeof value === 'string') {
        return value.split(UPSTREAM_PRODUCT_NAME).join(GOREECLOUD_PRODUCT_NAME);
    }

    if (Array.isArray(value)) {
        return value.map(replaceProductName);
    }

    if (value && typeof value === 'object') {
        return Object.fromEntries(
            Object.entries(value).map(([key, child]) => [key, replaceProductName(child)]),
        ) as TranslationObject;
    }

    return value;
};

const applyProductIdentity = () => {
    Object.keys(i18n.store.data).forEach((language) => {
        const bundle = i18n.getResourceBundle(language, 'translation') as TranslationObject | undefined;

        if (!bundle) {
            return;
        }

        const rebrandedBundle = replaceProductName(bundle) as TranslationObject;
        i18n.addResourceBundle(language, 'translation', rebrandedBundle, true, true);
    });
};

if (i18n.isInitialized) {
    applyProductIdentity();
} else {
    i18n.on('initialized', applyProductIdentity);
}

export { GOREECLOUD_PRODUCT_NAME, UPSTREAM_PRODUCT_NAME, applyProductIdentity };
