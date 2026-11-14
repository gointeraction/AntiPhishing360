import type { RequestContext } from '../types.ts';
import { CryptoService } from '../services/crypto.service.ts';
import { CommercialRepository } from '../repositories/commercial.repository.ts';
import { jsonResponse } from '../middlewares/security.middleware.ts';
import { RateLimitMiddleware } from '../middlewares/rateLimit.middleware.ts';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

export class CommercialController {
  static async getLandingFeed(rc: RequestContext): Promise<Response> {
    const cacheKey = 'commercial:landing_feed';
    const cached = await rc.env.KV_CACHE.get<Record<string, unknown>>(cacheKey, 'json');
    if (cached) {
      return jsonResponse({
        success: true,
        cached: true,
        data: cached,
      });
    }

    const repo = new CommercialRepository(rc.env.DB);
    const feedData = await repo.getLandingFeedData();

    await rc.env.KV_CACHE.put(cacheKey, JSON.stringify(feedData), { expirationTtl: 60 });

    return jsonResponse({
      success: true,
      cached: false,
      data: feedData,
    });
  }

  static async createLead(rc: RequestContext): Promise<Response> {
    // Strict 5 requests per hour per IP on commercial plan leads
    const rl = await RateLimitMiddleware.enforce({
      kv: rc.env.KV_CACHE,
      bucketName: 'commercial_leads',
      identifier: rc.clientIp,
      maxRequests: 5,
      windowSeconds: 3600,
      friendlyMessage:
        'Ya hemos recibido varias solicitudes desde tu conexión recientemente. Nuestro equipo te contactará muy pronto.',
    });
    if (rl) return rl;

    let body: Record<string, unknown>;
    try {
      body = (await rc.request.json()) as Record<string, unknown>;
    } catch {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'INVALID_LEAD_DATA',
            message: 'Por favor verifica tu correo electrónico y selecciona un plan válido',
          },
        },
        400
      );
    }

    const planSelected = typeof body.plan_selected === 'string' ? body.plan_selected.trim() : '';
    const fullName = typeof body.full_name === 'string' ? body.full_name.trim() : '';
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const phoneOrDomain =
      typeof body.phone_or_domain === 'string' ? body.phone_or_domain.trim() : '';
    const notes = typeof body.notes === 'string' ? body.notes.trim() : null;

    if (
      (planSelected !== 'family_shield' && planSelected !== 'verified_merchant') ||
      fullName.length < 2 ||
      !EMAIL_REGEX.test(email) ||
      phoneOrDomain.length < 4
    ) {
      return jsonResponse(
        {
          success: false,
          error: {
            code: 'INVALID_LEAD_DATA',
            message: 'Por favor verifica tu correo electrónico y selecciona un plan válido',
          },
        },
        400
      );
    }

    const repo = new CommercialRepository(rc.env.DB);
    const lead = await repo.createLead({
      id: CryptoService.generateUlid('led'),
      userId: rc.user ? rc.user.id : null,
      planSelected,
      fullName,
      email,
      phoneOrDomain,
      notes,
    });

    const planDisplayName =
      planSelected === 'family_shield' ? 'Plan Escudo Familiar' : 'Plan Comercio Verificado';

    return jsonResponse(
      {
        success: true,
        message: `¡Solicitud recibida! Te hemos enviado los detalles para activar tu ${planDisplayName}.`,
        data: lead,
      },
      201
    );
  }
}
