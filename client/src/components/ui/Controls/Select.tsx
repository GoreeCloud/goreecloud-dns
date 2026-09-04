import React, { ComponentProps, forwardRef, useRef } from 'react';
import clsx from 'clsx';

let selectIdCounter = 0;

const createSelectId = () => {
    selectIdCounter += 1;
    return `goreecloud-select-${selectIdCounter}`;
};

type SelectProps = ComponentProps<'select'> & {
    label?: string;
    error?: string;
};

export const Select = forwardRef<HTMLSelectElement, SelectProps>(
    ({ name, id, label, className, error, children, ...rest }, ref) => {
        const generatedId = useRef<string | null>(null);

        if (!generatedId.current) {
            generatedId.current = createSelectId();
        }

        const selectId = id ?? name ?? generatedId.current;
        const errorId = error ? `${selectId}-error` : undefined;
        const describedBy = [rest['aria-describedby'], errorId].filter(Boolean).join(' ') || undefined;

        return (
            <div className={clsx('form-group', { 'has-error': !!error })}>
                {label && (
                    <label className="form__label" htmlFor={selectId}>
                        {label}
                    </label>
                )}
                <div className="input-group">
                    <select
                        {...rest}
                        id={selectId}
                        name={name}
                        className={clsx('form-control custom-select', { 'is-invalid': !!error }, className)}
                        ref={ref}
                        aria-invalid={error ? true : undefined}
                        aria-describedby={describedBy}>
                        {children}
                    </select>
                </div>
                {error && (
                    <div id={errorId} className="form__message form__message--error mt-1" role="alert">
                        {error}
                    </div>
                )}
            </div>
        );
    },
);

Select.displayName = 'Select';
