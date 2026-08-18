import React, { memo } from 'react';

type Props = {
    className?: string;
};

export const Logo = memo(({ className }: Props) => {
    return (
        <svg
            xmlns="http://www.w3.org/2000/svg"
            width="190"
            height="40"
            viewBox="0 0 190 40"
            className={className}
            role="img"
            aria-label="GoreeCloud DNS"
        >
            <title>GoreeCloud DNS</title>
            <g fill="currentColor">
                <path d="M19.5 3.5c5.1 0 9.8 1.1 14 3.3v9.3c0 8.6-4.7 15.4-14 20.4-9.3-5-14-11.8-14-20.4V6.8c4.2-2.2 8.9-3.3 14-3.3Zm0 4.2c-3.4 0-6.7.7-9.8 2.1v6.3c0 6.5 3.3 11.7 9.8 15.7 6.5-4 9.8-9.2 9.8-15.7V9.8c-3.1-1.4-6.4-2.1-9.8-2.1Z" />
                <path d="M14.1 20.1a4.6 4.6 0 0 1 4.3-4.6 6.3 6.3 0 0 1 11.6 2.1 3.7 3.7 0 0 1-.7 7.3H17.8a3.8 3.8 0 0 1-3.7-4.8Z" opacity="0.72" />
            </g>
            <text x="43" y="18" fontFamily="system-ui, sans-serif" fontSize="15" fontWeight="700" fill="currentColor">
                GoreeCloud
            </text>
            <text x="43" y="32" fontFamily="system-ui, sans-serif" fontSize="12" fontWeight="600" fill="currentColor" opacity="0.72">
                DNS
            </text>
        </svg>
    );
});

Logo.displayName = 'Logo';
