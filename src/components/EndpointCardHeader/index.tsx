import classnames from 'classnames';
import React, { memo } from 'react';

import { ServiceCard } from '~/domain/service-map';

import { EndpointLogo } from './EndpointLogo';

import css from './styles.scss';

export interface Props {
  card: ServiceCard;
  currentNamespace?: string | null;
  onHeadlineClick?: () => void;
}

export const EndpointCardHeader = memo(function EndpointCardHeader(props: Props) {
  const { card, currentNamespace } = props;
  const showNamespace = !!card.namespace && card.namespace !== currentNamespace;

  // NOTE: Only the policy view sets these flags, live cards never carry them
  const defaultDeny = [
    card.service.ingressPolicyEnforced ? 'ingress' : null,
    card.service.egressPolicyEnforced ? 'egress' : null,
  ].filter(dir => dir != null);
  const policyNote = defaultDeny.length > 0 ? `default deny: ${defaultDeny.join(', ')}` : null;

  const titleClassName = classnames(css.title, {
    [css.single]: !showNamespace,
  });

  return (
    <div className={css.wrapper}>
      <div className={css.headline} onClick={props.onHeadlineClick}>
        <EndpointLogo card={card} />

        <div className={css.headings}>
          <div className={titleClassName}>{card.caption}</div>
          {showNamespace && <div className={css.subtitle}>{card.namespace}</div>}
          {policyNote != null && <div className={css.policyNote}>{policyNote}</div>}
        </div>
      </div>
    </div>
  );
});
