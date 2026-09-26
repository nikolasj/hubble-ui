export enum Application {
  ServiceMap = 'service-map',
  PolicyMap = 'policy-map',
}

export const APPLICATION_NAMES = new Set<string>(Object.values(Application));

export const getApplicationName = (app: Application): string => {
  return {
    [Application.ServiceMap]: 'Service Map',
    [Application.PolicyMap]: 'Policies',
  }[app];
};

export enum Order {
  Ascending = 'ascending',
  Descending = 'descending',
}

export enum Direction {
  Source = 'source',
  Destination = 'destination',
}
