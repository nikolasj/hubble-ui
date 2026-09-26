import React from 'react';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';

import { ServiceMapApp } from '~/components/ServiceMapApp';
import { PolicyMapApp } from '~/components/PolicyMapApp';

import { Router, ApplicationPath } from './router';
import { extractPathname } from './utils';

export type Props = {
  router: Router;
  RootComponent: React.JSX.Element;
};

export const Routes = function Routes(props: Props) {
  const router = createBrowserRouter(
    [
      {
        path: '/',
        element: props.RootComponent,
        children: [
          {
            path: ApplicationPath.ServiceMap,
            element: <ServiceMapApp />,
          },
          {
            path: ApplicationPath.PolicyMap,
            element: <PolicyMapApp />,
          },
        ],
      },
    ],
    {
      basename: extractPathname(document.querySelector('base')?.href ?? '/'),
    },
  );

  return <RouterProvider router={router} />;
};
