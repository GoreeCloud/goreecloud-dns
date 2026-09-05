import React, { useEffect } from 'react';

import { HashLink as Link } from 'react-router-hash-link';
import { Trans, useTranslation } from 'react-i18next';
import classNames from 'classnames';

import Statistics from './Statistics';
import Counters from './Counters';
import {
    DISABLE_PROTECTION_TIMINGS,
    FILTERS_URLS,
    MENU_URLS,
    ONE_SECOND_IN_MS,
    SETTINGS_URLS,
    TIME_UNITS,
} from '../../helpers/constants';
import { formatNumber, msToDays, msToHours, msToMinutes, msToSeconds } from '../../helpers/helpers';

import Loading from '../ui/Loading';
import './Dashboard.css';

import Dropdown from '../ui/Dropdown';
import UpstreamResponses from './UpstreamResponses';
import UpstreamAvgTime from './UpstreamAvgTime';
import { AccessData, DashboardData, StatsData } from '../../initialState';

interface DashboardProps {
    dashboard: DashboardData;
    stats: StatsData;
    access: AccessData;
    getStats: (...args: unknown[]) => unknown;
    getStatsConfig: (...args: unknown[]) => unknown;
    toggleProtection: (...args: unknown[]) => unknown;
    getClients: (...args: unknown[]) => unknown;
    getAccessList: () => (dispatch: any) => void;
}

type InsightMetricTone = 'accent' | 'success' | 'warning' | 'neutral';

interface InsightMetricProps {
    label: string;
    value: string;
    detail: string;
    testId: string;
    tone?: InsightMetricTone;
}

const InsightMetric = ({ label, value, detail, testId, tone = 'neutral' }: InsightMetricProps) => (
    <article className={`beacon-metric beacon-metric--${tone}`} data-testid={testId}>
        <span className="beacon-metric__label">{label}</span>
        <strong className="beacon-metric__value">{value}</strong>
        <span className="beacon-metric__detail">{detail}</span>
    </article>
);

const formatEndpoint = (address: string, port: number) => {
    const formattedAddress = address.includes(':') ? `[${address}]` : address;
    return `${formattedAddress}:${port}`;
};

const Dashboard = ({
    getAccessList,
    getStats,
    getStatsConfig,
    getClients,
    dashboard: {
        protectionEnabled,
        processingProtection,
        protectionDisabledDuration,
        dnsAddresses,
        dnsPort,
        dnsVersion,
        clients,
        autoClients,
        isCoreRunning,
    },
    toggleProtection,
    stats,
    access,
}: DashboardProps) => {
    const { t } = useTranslation();

    const getAllStats = () => {
        getAccessList();
        getClients();
        getStats();
        getStatsConfig();
    };

    useEffect(() => {
        getAllStats();
    }, []);

    const getSubtitle = () => {
        if (!stats.enabled) {
            return t('stats_disabled_short');
        }

        const msIn7Days = 604800000;

        if (stats.timeUnits === TIME_UNITS.HOURS && stats.interval === msIn7Days) {
            return t('for_last_days', { count: msToDays(stats.interval) });
        }

        return stats.timeUnits === TIME_UNITS.HOURS
            ? t('for_last_hours', { count: msToHours(stats.interval) })
            : t('for_last_days', { count: msToDays(stats.interval) });
    };

    const buttonClass = classNames('btn btn-sm dashboard-protection-button', {
        'btn-gray': protectionEnabled,
        'btn-success': !protectionEnabled,
    });

    const refreshButton = (
        <button
            type="button"
            className="btn btn-icon btn-outline-primary btn-sm"
            title={t('refresh_btn')}
            aria-label={t('refresh_btn')}
            onClick={() => getAllStats()}>
            <svg className="icons icon12" aria-hidden="true" focusable="false">
                <use xlinkHref="#refresh" />
            </svg>
        </button>
    );

    const statsProcessing = stats.processingStats || stats.processingGetConfig || access.processing;
    const subtitle = getSubtitle();

    const DISABLE_PROTECTION_ITEMS = [
        {
            text: t('disable_for_seconds', { count: msToSeconds(DISABLE_PROTECTION_TIMINGS.HALF_MINUTE) }),
            disableTime: DISABLE_PROTECTION_TIMINGS.HALF_MINUTE,
        },
        {
            text: t('disable_for_minutes', { count: msToMinutes(DISABLE_PROTECTION_TIMINGS.MINUTE) }),
            disableTime: DISABLE_PROTECTION_TIMINGS.MINUTE,
        },
        {
            text: t('disable_for_minutes', { count: msToMinutes(DISABLE_PROTECTION_TIMINGS.TEN_MINUTES) }),
            disableTime: DISABLE_PROTECTION_TIMINGS.TEN_MINUTES,
        },
        {
            text: t('disable_for_hours', { count: msToHours(DISABLE_PROTECTION_TIMINGS.HOUR) }),
            disableTime: DISABLE_PROTECTION_TIMINGS.HOUR,
        },
        {
            text: t('disable_until_tomorrow'),
            disableTime: DISABLE_PROTECTION_TIMINGS.TOMORROW,
        },
    ];

    const getDisableProtectionItems = () =>
        Object.values(DISABLE_PROTECTION_ITEMS).map((item: any, index: any) => (
            <button
                type="button"
                key={`disable_timings_${index}`}
                className="dropdown-item"
                onClick={() => {
                    toggleProtection(protectionEnabled, item.disableTime - ONE_SECOND_IN_MS);
                }}>
                {item.text}
            </button>
        ));

    const getRemainingTimeText = (milliseconds: any) => {
        if (!milliseconds) {
            return '';
        }

        const date = new Date(milliseconds);
        const hh = date.getUTCHours();
        const mm = `0${date.getUTCMinutes()}`.slice(-2);
        const ss = `0${date.getUTCSeconds()}`.slice(-2);
        const formattedHH = `0${hh}`.slice(-2);

        return hh ? `${formattedHH}:${mm}:${ss}` : `${mm}:${ss}`;
    };

    const getProtectionBtnText = (status: any) => (status ? t('disable_protection') : t('enable_protection'));

    const configuredClientCount = clients?.length ?? 0;
    const observedClientCount = autoClients?.length ?? 0;
    const endpointList = (dnsAddresses ?? []).map((address) => formatEndpoint(address, dnsPort));
    const upstreamNames = Array.from(
        new Set([
            ...(stats.topUpstreamsResponses ?? []).map(({ name }) => name),
            ...(stats.topUpstreamsAvgTime ?? []).map(({ name }) => name),
        ]),
    );
    const topUpstream = stats.topUpstreamsResponses?.[0]?.name ?? stats.topUpstreamsAvgTime?.[0]?.name;
    const safetyRewrites =
        stats.numReplacedSafebrowsing + stats.numReplacedParental + stats.numReplacedSafesearch;
    const protectionActions = stats.numBlockedFiltering + safetyRewrites;
    const protectionRate =
        stats.numDnsQueries > 0 ? `${((protectionActions / stats.numDnsQueries) * 100).toFixed(1)}%` : '0%';
    const averageProcessingTime = stats.avgProcessingTime ? `${Math.round(stats.avgProcessingTime)} ms` : '0 ms';

    const resolutionSteps = [
        {
            label: 'Clients',
            detail: `${formatNumber(configuredClientCount)} configured · ${formatNumber(observedClientCount)} observed`,
        },
        {
            label: 'DNS listener',
            detail: endpointList.length === 1 ? '1 service endpoint' : `${endpointList.length} service endpoints`,
        },
        {
            label: 'Protection',
            detail: protectionEnabled ? 'Filtering and policy active' : 'Filtering and policy paused',
        },
        {
            label: 'Resolver path',
            detail: 'Current configured DNS data plane',
        },
        {
            label: 'Upstream',
            detail:
                topUpstream ??
                (upstreamNames.length ? `${upstreamNames.length} observed` : 'No upstream statistics yet'),
        },
        {
            label: 'Response',
            detail: `${averageProcessingTime} average processing`,
        },
    ];

    const coreStatusClass = isCoreRunning ? 'beacon-status--success' : 'beacon-status--warning';
    const protectionStatusClass = protectionEnabled ? 'beacon-status--success' : 'beacon-status--warning';
    const clientMetricDetail = `${formatNumber(configuredClientCount)} configured · ${formatNumber(
        observedClientCount,
    )} observed`;

    return (
        <main className="beacon-dashboard" aria-labelledby="beacon-insights-title">
            <section className="beacon-hero" aria-describedby="beacon-insights-summary">
                <div className="beacon-hero__content">
                    <span className="beacon-eyebrow">GoreeCloud DNS</span>
                    <h1 id="beacon-insights-title" className="beacon-hero__title">
                        Beacon Insights
                    </h1>
                    <p id="beacon-insights-summary" className="beacon-hero__summary">
                        A privacy-minimized operational view of how DNS requests enter GoreeCloud, pass through protection,
                        reach the configured resolver path, and return to clients.
                    </p>

                    <div className="beacon-status-row" aria-label="DNS service status">
                        <span className={`beacon-status ${coreStatusClass}`}>
                            <span className="beacon-status__dot" aria-hidden="true" />
                            {isCoreRunning ? 'DNS service online' : 'DNS service state unavailable'}
                        </span>
                        <span className={`beacon-status ${protectionStatusClass}`}>
                            <span className="beacon-status__dot" aria-hidden="true" />
                            {protectionEnabled ? 'Protection active' : 'Protection paused'}
                        </span>
                        <span className="beacon-status beacon-status--neutral">Aggregate by default</span>
                    </div>
                </div>

                <div className="beacon-hero__actions">
                    <div className="beacon-protection-control">
                        <button
                            type="button"
                            className={buttonClass}
                            aria-pressed={protectionEnabled}
                            onClick={() => {
                                toggleProtection(protectionEnabled);
                            }}
                            disabled={processingProtection}>
                            {protectionDisabledDuration
                                ? `${t('enable_protection_timer', {
                                      time: getRemainingTimeText(protectionDisabledDuration),
                                  })}`
                                : getProtectionBtnText(protectionEnabled)}
                        </button>

                        {protectionEnabled && (
                            <Dropdown
                                label=""
                                baseClassName="dropdown-protection"
                                icon="arrow-down"
                                controlClassName="dropdown-protection__toggle"
                                menuClassName="dropdown-menu dropdown-menu-arrow dropdown-menu--protection">
                                {getDisableProtectionItems()}
                            </Dropdown>
                        )}
                    </div>

                    <button
                        type="button"
                        className="btn btn-outline-primary btn-sm beacon-refresh"
                        onClick={getAllStats}>
                        <svg className="icons icon12" aria-hidden="true" focusable="false">
                            <use xlinkHref="#refresh" />
                        </svg>
                        <Trans>refresh_statics</Trans>
                    </button>
                </div>
            </section>

            {statsProcessing && <Loading />}

            {!statsProcessing && (
                <>
                    {stats.interval === 0 && (
                        <div className="alert alert-warning" role="alert">
                            <Trans
                                components={[
                                    <Link to={`${SETTINGS_URLS.settings}#stats-config`} key="0">
                                        link
                                    </Link>,
                                ]}>
                                stats_disabled
                            </Trans>
                        </div>
                    )}

                    <section className="beacon-metrics" aria-label="DNS overview metrics">
                        <InsightMetric
                            label="DNS queries"
                            value={formatNumber(stats.numDnsQueries)}
                            detail={subtitle}
                            tone="accent"
                            testId="beacon-query-total"
                        />
                        <InsightMetric
                            label="Blocked by filters"
                            value={formatNumber(stats.numBlockedFiltering)}
                            detail={`${protectionRate} total protection-action rate`}
                            tone="warning"
                            testId="beacon-filtered-total"
                        />
                        <InsightMetric
                            label="Safety rewrites"
                            value={formatNumber(safetyRewrites)}
                            detail="Threat, parental, and Safe Search decisions"
                            tone="success"
                            testId="beacon-safety-total"
                        />
                        <InsightMetric
                            label="DNS clients"
                            value={formatNumber(configuredClientCount + observedClientCount)}
                            detail={clientMetricDetail}
                            testId="beacon-client-total"
                        />
                        <InsightMetric
                            label="Upstreams"
                            value={formatNumber(upstreamNames.length)}
                            detail={topUpstream ? `Most responses: ${topUpstream}` : 'Waiting for upstream statistics'}
                            testId="beacon-upstream-total"
                        />
                        <InsightMetric
                            label="Average processing"
                            value={averageProcessingTime}
                            detail="Aggregate DNS request processing time"
                            testId="beacon-latency"
                        />
                    </section>

                    <section className="beacon-resolution" aria-labelledby="beacon-resolution-title">
                        <div className="beacon-section-heading">
                            <div>
                                <span className="beacon-eyebrow">Request flow</span>
                                <h2 id="beacon-resolution-title">DNS Resolution Path</h2>
                            </div>
                            <p>
                                This reflects the currently configured DNS data plane. Native Beacon resolver stages are shown
                                here only when runtime evidence exposes them.
                            </p>
                        </div>

                        <ol className="beacon-resolution__track" aria-label="DNS resolution path">
                            {resolutionSteps.map(({ label, detail }, index) => (
                                <li className="beacon-resolution__step" key={label}>
                                    <span className="beacon-resolution__number" aria-hidden="true">
                                        {index + 1}
                                    </span>
                                    <span className="beacon-resolution__label">{label}</span>
                                    <span className="beacon-resolution__detail">{detail}</span>
                                </li>
                            ))}
                        </ol>
                    </section>

                    <section className="beacon-service-grid" aria-label="DNS service and detailed activity">
                        <article className="beacon-panel beacon-panel--endpoints">
                            <div className="beacon-section-heading beacon-section-heading--compact">
                                <div>
                                    <span className="beacon-eyebrow">Service addressing</span>
                                    <h2>DNS endpoints</h2>
                                </div>
                            </div>

                            {endpointList.length ? (
                                <ul className="beacon-endpoint-list" data-testid="beacon-endpoints">
                                    {endpointList.map((endpoint) => (
                                        <li key={endpoint}>
                                            <code>{endpoint}</code>
                                            <span>DNS listener</span>
                                        </li>
                                    ))}
                                </ul>
                            ) : (
                                <p className="beacon-empty-state">
                                    No DNS listener address is available in the current runtime state.
                                </p>
                            )}

                            <div className="beacon-version-row">
                                <span>Current service version</span>
                                <strong>{dnsVersion || 'Unavailable'}</strong>
                            </div>
                        </article>

                        <article className="beacon-panel beacon-panel--privacy">
                            <div className="beacon-section-heading beacon-section-heading--compact">
                                <div>
                                    <span className="beacon-eyebrow">Privacy boundary</span>
                                    <h2>Detailed activity stays deliberate</h2>
                                </div>
                            </div>
                            <p>
                                Beacon Insights keeps the landing page aggregate-first. Raw domain activity and identifiable
                                client details are not repeated here merely for dashboard richness; administrators can open the
                                authoritative detailed views when needed.
                            </p>
                            <div className="beacon-deep-links" aria-label="Detailed DNS administration views">
                                <Link className="btn btn-outline-primary btn-sm" to={MENU_URLS.logs}>
                                    Open Query Log
                                </Link>
                                <Link className="btn btn-outline-primary btn-sm" to={SETTINGS_URLS.clients}>
                                    Manage Clients
                                </Link>
                                <Link className="btn btn-outline-primary btn-sm" to={SETTINGS_URLS.dns}>
                                    DNS Settings
                                </Link>
                                <Link className="btn btn-outline-primary btn-sm" to={FILTERS_URLS.dns_blocklists}>
                                    Filter Lists
                                </Link>
                            </div>
                        </article>
                    </section>

                    <section className="beacon-activity" aria-labelledby="beacon-activity-title">
                        <div className="beacon-section-heading">
                            <div>
                                <span className="beacon-eyebrow">Aggregate activity</span>
                                <h2 id="beacon-activity-title">Queries and protection</h2>
                            </div>
                            <p>Trend cards summarize activity without putting raw query names on the overview surface.</p>
                        </div>
                        <Statistics
                            dnsQueries={stats.dnsQueries}
                            blockedFiltering={stats.blockedFiltering}
                            replacedSafebrowsing={stats.replacedSafebrowsing}
                            replacedParental={stats.replacedParental}
                            numDnsQueries={stats.numDnsQueries}
                            numBlockedFiltering={stats.numBlockedFiltering}
                            numReplacedSafebrowsing={stats.numReplacedSafebrowsing}
                            numReplacedParental={stats.numReplacedParental}
                        />
                    </section>

                    <section className="beacon-detail-grid" aria-label="DNS statistics and upstream details">
                        <div>
                            <Counters subtitle={subtitle} refreshButton={refreshButton} />
                        </div>
                        <div>
                            <UpstreamResponses
                                subtitle={subtitle}
                                topUpstreamsResponses={stats.topUpstreamsResponses}
                                refreshButton={refreshButton}
                            />
                        </div>
                        <div>
                            <UpstreamAvgTime
                                subtitle={subtitle}
                                topUpstreamsAvgTime={stats.topUpstreamsAvgTime}
                                refreshButton={refreshButton}
                            />
                        </div>
                    </section>
                </>
            )}
        </main>
    );
};

export default Dashboard;
