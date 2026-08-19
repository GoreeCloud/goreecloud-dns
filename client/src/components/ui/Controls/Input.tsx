import React, { ComponentProps, forwardRef, ReactNode, useRef } from 'react';
import clsx from 'clsx';

let inputIdCounter = 0;

const createInputId = () => {
    inputIdCounter += 1;
    return `goreecloud-input-${inputIdCounter}`;
};

type Props = ComponentProps<'input'> & {
    label?: string;
    desc?: string;
    leftAddon?: ReactNode;
    rightAddon?: ReactNode;
    error?: string;
    trimOnBlur?: boolean;
};

export const Input = forwardRef<HTMLInputElement, Props>(
    ({ name, id, label, desc, className, leftAddon, rightAddon, error, trimOnBlur, onBlur, ...rest }, ref) => {
        const generatedId = useRef<string | null>(null);

        if (!generatedId.current) {
            generatedId.current = createInputId();
        }

        const inputId = id ?? name ?? generatedId.current;
        const descId = desc ? `${inputId}-description` : undefined;
        const errorId = error ? `${inputId}-error` : undefined;
        const describedBy = [rest['aria-describedby'], descId, errorId].filter(Boolean).join(' ') || undefined;

        return (
            <div className={clsx('form-group', { 'has-error': !!error })}>
                {label && (
                    <label className={clsx('form__label', { 'form__label--with-desc': !!desc })} htmlFor={inputId}>
                        {label}
                    </label>
                )}
                {desc && (
                    <div id={descId} className="form__desc form__desc--top">
                        {desc}
                    </div>
                )}
                <div className="input-group">
                    {leftAddon && <div>{leftAddon}</div>}
                    <input
                        {...rest}
                        id={inputId}
                        name={name}
                        className={clsx('form-control', { 'is-invalid': !!error }, className)}
                        ref={ref}
                        aria-invalid={error ? true : undefined}
                        aria-describedby={describedBy}
                        onBlur={(e) => {
                            if (trimOnBlur) {
                                e.target.value = e.target.value.trim();
                                rest.onChange?.(e);
                            }
                            onBlur?.(e);
                        }}
                    />
                    {rightAddon && <div>{rightAddon}</div>}
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

Input.displayName = 'Input';