import React, { ComponentProps, forwardRef, useRef } from 'react';
import clsx from 'clsx';
import { trimLinesAndRemoveEmpty } from '../../../helpers/helpers';

let textareaIdCounter = 0;

const createTextareaId = () => {
    textareaIdCounter += 1;
    return `goreecloud-textarea-${textareaIdCounter}`;
};

type Props = ComponentProps<'textarea'> & {
    className?: string;
    wrapperClassName?: string;
    label?: string;
    desc?: string;
    error?: string;
    trimOnBlur?: boolean;
};

export const Textarea = forwardRef<HTMLTextAreaElement, Props>(
    ({ name, id, label, desc, className, wrapperClassName, error, trimOnBlur, onBlur, ...rest }, ref) => {
        const generatedId = useRef<string | null>(null);

        if (!generatedId.current) {
            generatedId.current = createTextareaId();
        }

        const textareaId = id ?? name ?? generatedId.current;
        const descId = desc ? `${textareaId}-description` : undefined;
        const errorId = error ? `${textareaId}-error` : undefined;
        const describedBy = [rest['aria-describedby'], descId, errorId].filter(Boolean).join(' ') || undefined;

        return (
            <div className={clsx('form-group', wrapperClassName, { 'has-error': !!error })}>
                {label && (
                    <label className={clsx('form__label', { 'form__label--with-desc': !!desc })} htmlFor={textareaId}>
                        {label}
                    </label>
                )}
                {desc && (
                    <div id={descId} className="form__desc form__desc--top">
                        {desc}
                    </div>
                )}
                <textarea
                    {...rest}
                    id={textareaId}
                    name={name}
                    className={clsx(
                        'form-control form-control--textarea form-control--textarea-small font-monospace',
                        { 'is-invalid': !!error },
                        className,
                    )}
                    ref={ref}
                    aria-invalid={error ? true : undefined}
                    aria-describedby={describedBy}
                    onBlur={(e) => {
                        if (trimOnBlur) {
                            const normalizedValue = trimLinesAndRemoveEmpty(e.target.value);
                            const onValueChange = rest.onChange as ((value: string) => void) | undefined;
                            onValueChange?.(normalizedValue);
                        }
                        onBlur?.(e);
                    }}
                />
                {error && (
                    <div id={errorId} className="form__message form__message--error" role="alert">
                        {error}
                    </div>
                )}
            </div>
        );
    },
);

Textarea.displayName = 'Textarea';
