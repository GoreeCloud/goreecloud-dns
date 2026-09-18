import React, { forwardRef, ReactNode } from 'react';

type Props<T> = {
    name: string;
    value: T;
    onChange: (e: T) => void;
    options: { label: string; desc?: ReactNode; value: T }[];
    disabled?: boolean;
    error?: string;
};

export const Radio = forwardRef<HTMLInputElement, Props<string | boolean | number | undefined>>(
    ({ disabled, onChange, value, options, name, error, ...rest }, ref) => {
        const getId = (label: string) => (name ? `${label}_${name}` : label);
        const errorId = error ? `${name}-error` : undefined;

        return (
            <div role="radiogroup" aria-invalid={error ? true : undefined} aria-describedby={errorId}>
                {options.map((o) => {
                    const checked = value === o.value;

                    return (
                        <label
                            key={`${getId(o.label)}`}
                            htmlFor={getId(o.label)}
                            className="custom-control custom-radio">
                            <input
                                id={getId(o.label)}
                                name={name}
                                data-testid={o.value}
                                type="radio"
                                className="custom-control-input"
                                onChange={() => onChange(o.value)}
                                checked={checked}
                                disabled={disabled}
                                ref={ref}
                                {...rest}
                            />

                            <span className="custom-control-label">{o.label}</span>

                            {o.desc && <span className="checkbox__label-subtitle">{o.desc}</span>}
                        </label>
                    );
                })}
                {!disabled && error && (
                    <span id={errorId} className="form__message form__message--error" role="alert">
                        {error}
                    </span>
                )}
            </div>
        );
    },
);

Radio.displayName = 'Radio';
