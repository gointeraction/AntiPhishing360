import { RouteHandler } from './types/env';

interface RegisteredRoute {
  method: string;
  segments: string[];
  handler: RouteHandler;
}

export class Router {
  private readonly routes: RegisteredRoute[] = [];

  public register(method: string, path: string, handler: RouteHandler): void {
    const cleanSegments = path
      .replace(/^\/+|\/+$/g, '')
      .split('/')
      .filter(Boolean);

    this.routes.push({
      method: method.toUpperCase(),
      segments: cleanSegments,
      handler
    });
  }

  public get(path: string, handler: RouteHandler): void {
    this.register('GET', path, handler);
  }

  public post(path: string, handler: RouteHandler): void {
    this.register('POST', path, handler);
  }

  public delete(path: string, handler: RouteHandler): void {
    this.register('DELETE', path, handler);
  }

  public match(
    method: string,
    pathname: string
  ): { handler: RouteHandler; params: Record<string, string> } | null {
    const upperMethod = method.toUpperCase();
    const reqSegments = pathname
      .replace(/^\/+|\/+$/g, '')
      .split('/')
      .filter(Boolean);

    for (const route of this.routes) {
      if (route.method !== upperMethod) continue;
      if (route.segments.length !== reqSegments.length) continue;

      const params: Record<string, string> = {};
      let matched = true;

      for (let i = 0; i < route.segments.length; i++) {
        const routeSeg = route.segments[i]!;
        const reqSeg = reqSegments[i]!;

        if (routeSeg.startsWith(':')) {
          const paramName = routeSeg.slice(1);
          params[paramName] = decodeURIComponent(reqSeg);
        } else if (routeSeg !== reqSeg) {
          matched = false;
          break;
        }
      }

      if (matched) {
        return { handler: route.handler, params };
      }
    }

    return null;
  }
}
