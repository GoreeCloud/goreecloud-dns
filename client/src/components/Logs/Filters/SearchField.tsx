import React, { ComponentProps } from 'react';
import Tooltip from '../../ui/Tooltip';

interface Props extends ComponentProps<'input'> {
    handleChange: (newValue: string) => void;
    onClear: () => void;
    clearLabel: string;
    tooltip?: string;
}

export const SearchField = ({
    handleChange,
    onClear,
    clearLabel,
    value,
    tooltip,
    className,
    id,
    'aria-describedby': ariaDescribedBy,
    ...rest
}: Props) => {
    const helpId = tooltip && id ? `${id}-help` : undefined;
    const describedBy = [ariaDescribedBy, helpId].filter(Boolean).join(' ') || undefined;

    const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        handleChange(e.target.value);
    };

    const handleBlur = (e: React.FocusEvent<HTMLInputElement>) => {
        e.target.value = e.target.value.trim();
        handleChange(e.target.value);
    };

    return (
        <>
            <div className="input-group-search input-group-search__icon--magnifier">
                <svg className="icons icon--24 icon--gray" aria-hidden="true" focusable="false">
                    <use xlinkHref="#magnifier" />
                </svg>
            </div>
            <input
                {...rest}
                id={id}
                aria-describedby={describedBy}
                className={className}
                value={value}
                onChange={handleInputChange}
                onBlur={handleBlur}
            />
            {tooltip && helpId && (
                <span id={helpId} className="sr-only">
                    {tooltip}
                </span>
            )}
            {typeof value === 'string' && value.length > 0 && (
                <button
                    type="button"
                    className="btn btn-icon input-group-search input-group-search__icon--cross"
                    aria-label={clearLabel}
                    onClick={onClear}
                >
                    <svg className="icons icon--20 icon--gray" aria-hidden="true" focusable="false">
                        <use xlinkHref="#cross" />
                    </svg>
                </button>
            )}
            {tooltip && (
                <span className="input-group-search input-group-search__icon--tooltip">
                    <Tooltip content={tooltip} className="tooltip-container">
                        <svg className="icons icon--20 icon--gray" aria-hidden="true" focusable="false">
                            <use xlinkHref="#question" />
                        </svg>
                    </Tooltip>
                </span>
            )}
        </>
    );
};
