import type { RequestContext } from './types.ts';
import { AuthController } from './controllers/auth.controller.ts';
import { ScanController } from './controllers/scan.controller.ts';
import { CommercialController } from './controllers/commercial.controller.ts';
import { CommunityController } from './controllers/community.controller.ts';
import { CicpcController } from './controllers/cicpc.controller.ts';
import { jsonResponse } from './middlewares/security.middleware.ts';

type RouteHandler = (rc: RequestContext) => Promise<Response>;

interface RouteEntry {
  method: string;
  pattern: RegExp;
  paramNames: string[];
  handler: RouteHandler;
}

export class ApiRouter {
  private routes: RouteEntry[] = [];

  constructor() {
    // Healthcheck
    this.add('GET', '/api/v1/health', async () =>
      jsonResponse({
        success: true,
        service: 'detector360-edge-api',
        status: 'operational',
        timestamp: new Date().toISOString(),
      })
    );

    // Module 1: Auth & Conversion
    this.add('POST', '/api/v1/auth/register', AuthController.register);
    this.add('POST', '/api/v1/auth/login', AuthController.login);
    this.add('POST', '/api/v1/auth/logout', AuthController.logout);
    this.add('GET', '/api/v1/auth/me', AuthController.me);

    // Module 2: Live Forensic Scanner
    this.add('POST', '/api/v1/scans', ScanController.createScan);
    this.add('GET', '/api/v1/scans/history', ScanController.getUserHistory);
    this.add('GET', '/api/v1/scans/:scan_id', ScanController.getScanById);
    this.add('POST', '/api/v1/scans/:scan_id/feedback', ScanController.submitClarityFeedback);

    // Module 3: Commercial Metrics, Plans & Community Alerts
    this.add('GET', '/api/v1/commercial/landing-feed', CommercialController.getLandingFeed);
    this.add('POST', '/api/v1/commercial/leads', CommercialController.createLead);
    this.add('GET', '/api/v1/community/alerts', CommunityController.listAlerts);
    this.add('POST', '/api/v1/community/alerts', CommunityController.publishAlert);

    // Module 4: Restricted C.I.C.P.C Cybercrime Command & Case Management
    this.add('POST', '/api/v1/cicpc/cases/report', CicpcController.submitCitizenCase);
    this.add('POST', '/api/v1/cicpc/auth/login', CicpcController.officerLogin);
    this.add('POST', '/api/v1/cicpc/auth/logout', CicpcController.officerLogout);
    this.add('GET', '/api/v1/cicpc/auth/me', CicpcController.officerSession);
    this.add('GET', '/api/v1/cicpc/dashboard', CicpcController.getDashboardOverview);
    this.add('GET', '/api/v1/cicpc/cases', CicpcController.listCases);
    this.add('GET', '/api/v1/cicpc/cases/:case_id', CicpcController.getCaseDetail);
    this.add('PATCH', '/api/v1/cicpc/cases/:case_id', CicpcController.updateCaseDecision);
  }

  private add(method: string, pathTemplate: string, handler: RouteHandler): void {
    const paramNames: string[] = [];
    const regexSource = pathTemplate
      .replace(/\/:([a-zA-Z0-9_]+)/g, (_full, paramName: string) => {
        paramNames.push(paramName);
        return '/([^/]+)';
      })
      .replace(/\//g, '\\/');

    this.routes.push({
      method: method.toUpperCase(),
      pattern: new RegExp(`^${regexSource}\\/?$`),
      paramNames,
      handler,
    });
  }

  async dispatch(rc: RequestContext): Promise<Response> {
    const url = new URL(rc.request.url);
    const pathname = url.pathname;
    const method = rc.request.method.toUpperCase();

    for (const route of this.routes) {
      if (route.method !== method) continue;
      const match = pathname.match(route.pattern);
      if (!match) continue;

      const params: Record<string, string> = {};
      route.paramNames.forEach((name, idx) => {
        params[name] = decodeURIComponent(match[idx + 1]);
      });

      rc.params = params;
      return await route.handler(rc);
    }

    return jsonResponse(
      {
        success: false,
        error: {
          code: 'ENDPOINT_NOT_FOUND',
          message: `Ruta de API no encontrada: ${method} ${pathname}`,
        },
      },
      404
    );
  }
}
