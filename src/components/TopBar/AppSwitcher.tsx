import React from 'react';
import { Button, ButtonGroup } from '@blueprintjs/core';
import type { IconName } from '@blueprintjs/icons';

import { Application, getApplicationName } from '~/domain/common';

export interface Props {
  currentApp: Application;
  onAppChange?: (app: Application) => void;
}

const apps: Array<[Application, IconName]> = [
  [Application.ServiceMap, 'graph'],
  [Application.PolicyMap, 'shield'],
];

export const AppSwitcher = function AppSwitcher(props: Props) {
  return (
    <ButtonGroup>
      {apps.map(([app, icon]) => (
        <Button
          key={app}
          small
          active={props.currentApp === app}
          icon={icon}
          text={getApplicationName(app)}
          onClick={() => props.onAppChange?.(app)}
        />
      ))}
    </ButtonGroup>
  );
};
