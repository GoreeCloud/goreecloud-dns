import React from 'react';
import { Trans, useTranslation } from 'react-i18next';

import { INSTALL_TOTAL_STEPS } from '../../helpers/constants';

const getProgressPercent = (step: number) => (step / INSTALL_TOTAL_STEPS) * 100;

type Props = {
    step: number;
};

export const Progress = ({ step }: Props) => {
    const { t } = useTranslation();

    return (
        <div className="setup__progress">
            <Trans>install_step</Trans> {step}/{INSTALL_TOTAL_STEPS}
            <div
                className="setup__progress-wrap"
                role="progressbar"
                aria-label={t('install_step')}
                aria-valuemin={0}
                aria-valuemax={INSTALL_TOTAL_STEPS}
                aria-valuenow={step}
                aria-valuetext={`${step}/${INSTALL_TOTAL_STEPS}`}>
                <div
                    className="setup__progress-inner"
                    style={{ width: `${getProgressPercent(step)}%` }}
                    aria-hidden="true"
                />
            </div>
        </div>
    );
};
