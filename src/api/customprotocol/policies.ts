import { Oneshot, OneshotOptions, StreamEvent, Message } from '~/api/customprotocol-core';

import * as uipb from '~backend/proto/ui/ui_pb';

export enum Event {
  Response = 'response',
}

export type Handlers = {
  [Event.Response]: (resp: uipb.GetPoliciesResponse) => void;
};

export type Options = OneshotOptions & {
  namespace: string;
};

// PoliciesRequest asks the backend once for the policy graph of a namespace.
export class PoliciesRequest extends Oneshot<Handlers> {
  private namespace: string;

  constructor(opts: Options) {
    super(opts);

    this.namespace = opts.namespace;
    this.setupEventHandlers();
  }

  public onResponse(fn: Handlers[Event.Response]): this {
    this.on(Event.Response, fn);
    return this;
  }

  private setupEventHandlers() {
    this.on(StreamEvent.Message, msg => {
      const resp = uipb.GetPoliciesResponse.fromBinary(msg.body);

      this.emit(Event.Response, resp);
    });
  }

  protected messageBuilder(msg: Message, isFirst: boolean): Message {
    if (!isFirst) return msg;

    const req = uipb.GetPoliciesRequest.create({ namespace: this.namespace });
    const bytes = uipb.GetPoliciesRequest.toBinary(req);

    return msg.setBodyBytes(bytes);
  }
}
