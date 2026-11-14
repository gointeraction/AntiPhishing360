import type { RiskLevel, ScanFindingDTO } from '../types.ts';
import { CryptoService } from './crypto.service.ts';
import { AntiphishingCtiService } from './url-heuristics.service.ts';

export interface SeniorTrainingQuestion {
  id: string;
  step: number;
  sender_label: string;
  channel: 'WhatsApp' | 'SMS' | 'Correo';
  message_text: string;
  correct_answer: 'SCAM' | 'SAFE';
  clue_highlight: string;
  explanation_calm: string;
}

export interface SeniorMessageAnalysisDTO {
  scan_id: string;
  analyzed_at: string;
  extracted_urls: string[];
  primary_url: string;
  risk_score: number;
  risk_level: RiskLevel;
  requires_anti_panic_pause: boolean;
  impersonated_entity: string;
  detected_scam_type: string;
  spoken_script: string;
  citizen_verdict: {
    title: string;
    summary: string;
    action_steps: string[];
  };
  findings: ScanFindingDTO[];
}

const URL_IN_TEXT_REGEX =
  /\b((?:https?:\/\/|www\.)[^\s<>()"']+|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xyz|top|click|online|site|shop|vip|icu|buzz|info|net|com|org|ve|es|co)(?:\/[^\s<>()"']*)?)/gi;

export class SeniorProtectionService {
  /**
   * Extrae enlaces explícitos u ocultos dentro de un mensaje de WhatsApp, SMS o texto OCR
   */
  static extractUrlsFromText(text: string): string[] {
    const matches = text.match(URL_IN_TEXT_REGEX) || [];
    const cleaned = new Set<string>();

    for (const raw of matches) {
      const trimmed = raw.replace(/[.,;:!?)]+$/, '').trim();
      if (!trimmed || trimmed.includes('@')) continue;
      // Evitar falsos positivos como "ej.com" o abreviaturas sin forma real de dominio
      if (trimmed.length < 6) continue;
      const withProto = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
      try {
        const u = new URL(withProto);
        if (u.hostname.includes('.')) {
          cleaned.add(u.toString());
        }
      } catch {
        // Ignorar fragmento inválido
      }
    }

    return Array.from(cleaned);
  }

  /**
   * Analiza mensajes completos de WhatsApp / SMS o textos de capturas de pantalla
   * combinando detección psicológica para adultos mayores + heurística de URLs Day-Zero
   */
  static async analyzeSeniorMessage(rawText: string): Promise<SeniorMessageAnalysisDTO> {
    const normalized = rawText.trim();
    const lower = normalized
      .toLowerCase()
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '');

    const findings: ScanFindingDTO[] = [];
    let score = 0;
    let requiresAntiPanicPause = false;
    let impersonatedEntity = 'Remitente no verificado';
    let detectedScamType = 'REVISION_PREVENTIVA';

    // 1. Estafa "Hola mamá / papá, cambié de número" (Suplantación familiar en WhatsApp)
    const hasFamilyGreeting =
      /\b(hola\s+(mama|papa|abuela|abuelo|tia|tio|mami|papi)|bendicion\s+(mama|papa|abuela|tia)|soy\s+tu\s+(hijo|hija|nieto|nieta))\b/.test(
        lower
      );
    const hasNewNumberExcuse =
      /\b(cambie\s+de\s+numero|nuevo\s+numero|se\s+me\s+(dano|rompio|perdio|cayo)\s+el\s+(celular|telefono)|agenda\s+este\s+numero|guarda\s+este\s+numero|telefono\s+prestado)\b/.test(
        lower
      );
    const hasMoneyRequest =
      /\b(prestame|transferencia|pago\s+movil|urgente|pagar\s+algo|favor\s+urgente|dinero|bolivares|dolares|zelle)\b/.test(
        lower
      );

    if ((hasFamilyGreeting && hasNewNumberExcuse) || (hasNewNumberExcuse && hasMoneyRequest)) {
      score += 72;
      requiresAntiPanicPause = true;
      impersonatedEntity = 'Familiar Cercano Suplantado (WhatsApp)';
      detectedScamType = 'SUPLANTACION_FAMILIAR_WHATSAPP';
      findings.push({
        id: CryptoService.generateUlid('fnd'),
        rule_code: 'SENIOR_FAMILY_IMPERSONATION',
        category: 'JS_SCRIPT',
        severity: 'CRITICAL',
        line_number: 1,
        column_number: 1,
        dom_selector: 'msg:suplantacion-familiar',
        citizen_explanation:
          'Detectamos la estafa clásica de "cambié de número": un extraño finge ser tu hijo, nieto o familiar con una urgencia para pedirte dinero.',
        technical_detail:
          'Patrón de ingeniería social afectiva detectado (saludo filial + excusa de cambio/daño de dispositivo + solicitud financiera).',
        code_snippet: normalized.slice(0, 140),
      });
    }

    // 2. Señuelo de Pensión / Bono / IVSS / Patria con vencimiento rápido
    const hasPensionOrBonus =
      /\b(pension|ivss|bono|patria|subsidio|adulto\s+mayor|abuelos|beneficio\s+social|asignacion\s+especial)\b/.test(
        lower
      );
    const hasClaimOrExpiry =
      /\b(vence|expira|minutos|horas|reclama|activar|actualiza|cobra|aceptar\s+bono|ultimo\s+dia|perderas)\b/.test(
        lower
      );

    if (hasPensionOrBonus && hasClaimOrExpiry) {
      score += 66;
      requiresAntiPanicPause = true;
      impersonatedEntity = 'Organismo de Pensión / Bono Social';
      detectedScamType = 'FALSA_PENSION_O_BONO';
      findings.push({
        id: CryptoService.generateUlid('fnd'),
        rule_code: 'SENIOR_PENSION_BONUS_LURE',
        category: 'DOM_FORM',
        severity: 'CRITICAL',
        line_number: 1,
        column_number: 1,
        dom_selector: 'msg:senuelo-pension-bono',
        citizen_explanation:
          'Ninguna pensión del IVSS ni bono oficial vence en pocos minutos ni se cobra abriendo enlaces recibidos por WhatsApp.',
        technical_detail:
          'Señuelo de beneficio social dirigido a personas mayores combinado con presión temporal artificial.',
        code_snippet: normalized.slice(0, 140),
      });
    }

    // 3. Robo de cuenta de WhatsApp o clave bancaria mediante código de 6 dígitos / premio
    const hasOtpCodeRequest =
      /\b(codigo\s+de\s+(6|seis)\s+digitos|codigo\s+de\s+verificacion|codigo\s+que\s+te\s+llego|pasame\s+el\s+codigo|reenviame\s+el\s+sms|clave\s+dinamica|tarjeta\s+de\s+coordenadas)\b/.test(
        lower
      );
    const hasFakePrize =
      /\b(ganaste|sorteo|premio|seleccionado|mercado\s+gratis|farmacia|regalo\s+aniversario)\b/.test(
        lower
      );

    if (hasOtpCodeRequest) {
      score += 75;
      requiresAntiPanicPause = true;
      impersonatedEntity = 'Secuestro de Cuenta WhatsApp / Banca';
      detectedScamType = 'ROBO_CODIGO_VERIFICACION';
      findings.push({
        id: CryptoService.generateUlid('fnd'),
        rule_code: 'SENIOR_OTP_HIJACK_ATTEMPT',
        category: 'DOM_INPUT',
        severity: 'CRITICAL',
        line_number: 1,
        column_number: 1,
        dom_selector: 'msg:robo-codigo-sms',
        citizen_explanation:
          'Te están pidiendo un código SMS o clave dinámica. Si lo entregas, tomarán el control de tu WhatsApp o de tu cuenta bancaria.',
        technical_detail:
          'Solicitud explícita de token OTP de segundo factor o clave dinámica bancaria.',
        code_snippet: normalized.slice(0, 140),
      });
    } else if (hasFakePrize) {
      score += 48;
      impersonatedEntity = 'Falso Sorteo Comercial';
      detectedScamType = 'SORTEO_FALSO';
      findings.push({
        id: CryptoService.generateUlid('fnd'),
        rule_code: 'SENIOR_FAKE_PRIZE_LURE',
        category: 'DOM_FORM',
        severity: 'HIGH',
        line_number: 1,
        column_number: 1,
        dom_selector: 'msg:falso-sorteo',
        citizen_explanation:
          'Desconfía de premios o sorteos en los que nunca te inscribiste; suelen usarse para robar tus datos o tu WhatsApp.',
        technical_detail: 'Señuelo promocional no solicitado detectado en el cuerpo del mensaje.',
        code_snippet: normalized.slice(0, 140),
      });
    }

    // 4. Coerción o pánico bancario / corte de servicio eléctrico
    const hasBankOrServicePanic =
      /\b(cuenta\s+(bloqueada|suspendida|restringida)|bloqueo\s+preventivo|acceso\s+no\s+reconocido|corte\s+inmediato|suspension\s+del\s+servicio|evite\s+el\s+bloqueo)\b/.test(
        lower
      );
    if (hasBankOrServicePanic) {
      score += 62;
      requiresAntiPanicPause = true;
      if (impersonatedEntity === 'Remitente no verificado') {
        impersonatedEntity = 'Entidad Bancaria o Servicio Público Suplantado';
      }
      detectedScamType = 'AMENAZA_BLOQUEO_BANCARIO';
      findings.push({
        id: CryptoService.generateUlid('fnd'),
        rule_code: 'SENIOR_BANK_PANIC_COERCION',
        category: 'TRANSPORT',
        severity: 'CRITICAL',
        line_number: 1,
        column_number: 1,
        dom_selector: 'msg:coercion-bloqueo-cuenta',
        citizen_explanation:
          'El mensaje intenta asustarte con un supuesto bloqueo de cuenta o corte de servicio para que actúes sin pensar.',
        technical_detail:
          'Coerción psicológica por amenaza de suspensión inmediata de cuenta bancaria o suministro básico.',
        code_snippet: normalized.slice(0, 140),
      });
    }

    // 5. Paquete retenido / Aduana / Encomienda
    const hasParcelScam =
      /\b(paquete\s+(retenido|pendiente|detenido)|direccion\s+incompleta|pago\s+de\s+aduana|impuesto\s+de\s+envio|entrega\s+fallida)\b/.test(
        lower
      );
    if (hasParcelScam) {
      score += 52;
      impersonatedEntity = 'Empresa de Envíos Suplantada';
      detectedScamType = 'PAQUETE_RETENIDO_FALSO';
      findings.push({
        id: CryptoService.generateUlid('fnd'),
        rule_code: 'SENIOR_PARCEL_TRAP',
        category: 'TRANSPORT',
        severity: 'HIGH',
        line_number: 1,
        column_number: 1,
        dom_selector: 'msg:paquete-retenido',
        citizen_explanation:
          'Las empresas de encomiendas reales no piden pagos sorpresivos con tarjeta mediante enlaces de texto.',
        technical_detail: 'Señuelo logístico de paquete retenido / tasa aduanera fraudulenta.',
        code_snippet: normalized.slice(0, 140),
      });
    }

    // 6. Presión extrema de tiempo ("en 10 minutos", "urgente ahora mismo")
    const hasExtremeUrgency =
      /\b(en\s+\d+\s+minutos|10\s+minutos|inmediatamente|ahora\s+mismo|ultimo\s+aviso|urgente)\b/.test(
        lower
      );
    if (hasExtremeUrgency) {
      requiresAntiPanicPause = true;
      if (score > 0) {
        score += 15;
      } else {
        score += 28;
        findings.push({
          id: CryptoService.generateUlid('fnd'),
          rule_code: 'SENIOR_EXTREME_TIME_PRESSURE',
          category: 'TRANSPORT',
          severity: 'MEDIUM',
          line_number: 1,
          column_number: 1,
          dom_selector: 'msg:presion-tiempo',
          citizen_explanation:
            'El mensaje usa prisa extrema ("urgente" o pocos minutos). Respira con calma: la prisa es la herramienta favorita del estafador.',
          technical_detail: 'Marcadores léxicos de presión temporal coercitiva.',
          code_snippet: normalized.slice(0, 140),
        });
      }
    }

    // 7. Inspección de cualquier enlace presente dentro del texto con AntiphishingCtiService
    const extractedUrls = this.extractUrlsFromText(normalized);
    for (const candidateUrl of extractedUrls.slice(0, 3)) {
      const urlFindings = await AntiphishingCtiService.analyzeUrl(candidateUrl);
      for (const uf of urlFindings) {
        findings.push(uf);
        if (uf.severity === 'CRITICAL') {
          score += 55;
          requiresAntiPanicPause = true;
        } else if (uf.severity === 'HIGH') {
          score += 35;
        } else {
          score += 18;
        }
      }
      if (urlFindings.length === 0 && candidateUrl.startsWith('http://')) {
        score += 25;
        findings.push({
          id: CryptoService.generateUlid('fnd'),
          rule_code: 'MSG_INSECURE_HTTP_LINK',
          category: 'TRANSPORT',
          severity: 'MEDIUM',
          line_number: 1,
          column_number: 1,
          dom_selector: 'msg:enlace-sin-candado',
          citizen_explanation: `El mensaje incluye un enlace sin candado de seguridad (${candidateUrl}). No escribas contraseñas allí.`,
          technical_detail: 'Enlace HTTP en texto plano detectado dentro del mensaje.',
          code_snippet: candidateUrl,
        });
      }
    }

    const finalScore = Math.max(0, Math.min(100, score));
    let riskLevel: RiskLevel = 'SAFE';
    if (finalScore >= 60 || findings.some((f) => f.severity === 'CRITICAL')) {
      riskLevel = 'CRITICAL';
      requiresAntiPanicPause = true;
    } else if (finalScore >= 25) {
      riskLevel = 'WARNING';
    }

    let title = 'Mensaje Tranquilo: No detectamos trampas ni enlaces peligrosos';
    let summary =
      'Revisamos las palabras del mensaje y no encontramos chantajes urgentes ni enlaces falsos conocidos. Aun así, recuerda nunca compartir tus claves bancarias.';
    let actionSteps = [
      'Si el mensaje es de un familiar, puedes conversar con tranquilidad.',
      'Recuerda que ningún banco pide contraseñas por chat.',
    ];
    let spokenScript =
      'Resultado en Verde. Mensaje tranquilo. No detectamos enlaces falsos ni frases de estafa en este texto.';

    if (riskLevel === 'CRITICAL') {
      title = 'PELIGRO ROJO: Este mensaje intenta engañarte. No respondas ni toques nada.';
      summary =
        findings[0]?.citizen_explanation ||
        'Detectamos señales claras de estafa dirigida a personas mayores y familias.';
      actionSteps = [
        'NO toques ningún enlace ni envíes dinero ni códigos de 6 dígitos.',
        'Si dice ser un hijo o familiar con número nuevo, cuelga y llámalo tú mismo a su número de siempre.',
        'Toca el botón "Preguntar a mi Familiar de Confianza" o borra el mensaje de inmediato.',
      ];
      spokenScript = `Atención. Semáforo en Rojo. Peligro detectado. ${summary} No toques ningún enlace, no entregues ninguna clave ni transfieras dinero. Si tienes dudas, toca el botón para consultar a tu familiar de confianza.`;
    } else if (riskLevel === 'WARNING') {
      title = 'AMARILLO DE PRECAUCIÓN: Este mensaje tiene señales dudosas. Verifica primero.';
      summary =
        findings[0]?.citizen_explanation ||
        'El mensaje contiene presión de tiempo o enlaces no verificados. Conviene confirmarlo antes de hacer nada.';
      actionSteps = [
        'No entregues datos personales ni números de tarjeta por mensaje.',
        'Consulta con tu familiar de confianza o busca el teléfono real en nuestro Directorio Oficial.',
      ];
      spokenScript = `Atención. Semáforo en Amarillo. Ten precaución con este mensaje. ${summary} Consulta primero con un familiar de confianza antes de responder.`;
    }

    const primaryUrl =
      extractedUrls[0] ||
      `https://mensaje-analizado.detector360.ejemplo/revision-${Date.now()}`;

    return {
      scan_id: CryptoService.generateUlid('scn'),
      analyzed_at: new Date().toISOString(),
      extracted_urls: extractedUrls,
      primary_url: primaryUrl,
      risk_score: finalScore,
      risk_level: riskLevel,
      requires_anti_panic_pause: requiresAntiPanicPause,
      impersonated_entity: impersonatedEntity,
      detected_scam_type: detectedScamType,
      spoken_script: spokenScript,
      citizen_verdict: {
        title,
        summary,
        action_steps: actionSteps,
      },
      findings,
    };
  }

  /**
   * 3 Retos Interactivos Semanales con Casos Reales para Adultos Mayores
   */
  static getTrainingSimulatorQuestions(): SeniorTrainingQuestion[] {
    return [
      {
        id: 'sim_q1_hijo_numero',
        step: 1,
        sender_label: 'Número desconocido (+58 412-998-0012)',
        channel: 'WhatsApp',
        message_text:
          '"Hola mamá, bendición. Se me cayó el teléfono en el agua y estoy escribiendo desde un número nuevo. Necesito hacer un pago urgente de $80 y el banco no me abre, ¿me puedes prestar por Pago Móvil y te devuelvo en la noche?"',
        correct_answer: 'SCAM',
        clue_highlight: 'Número desconocido + excusa de teléfono dañado + dinero urgente',
        explanation_calm:
          '¡Muy bien visto! Esta es la estafa de suplantación familiar más común. Antes de transferir un solo bolívar, llama tú mismo al número viejo de tu hijo o hazle una videollamada para ver su rostro.',
      },
      {
        id: 'sim_q2_bono_pension',
        step: 2,
        sender_label: 'Reenviado muchas veces en grupo vecinal',
        channel: 'WhatsApp',
        message_text:
          '"AVISO URGENTE PENSIONADOS: Activa hoy tu Bono Especial de Salud y Alimentación antes de que venza en 10 minutos ingresando tu cédula y clave bancaria aquí: http://bono-adultomayor-activo.xyz/cobrar"',
        correct_answer: 'SCAM',
        clue_highlight: 'Amenaza que "vence en 10 minutos" + pide clave bancaria en enlace .xyz',
        explanation_calm:
          '¡Excelente! Ninguna pensión ni beneficio oficial vence en 10 minutos ni jamás te pedirá la contraseña de tu banco por un enlace de WhatsApp.',
      },
      {
        id: 'sim_q3_aviso_informativo',
        step: 3,
        sender_label: 'Recordatorio Médico Clínica Santa Sofía',
        channel: 'SMS',
        message_text:
          '"Estimado paciente: Le recordamos su cita de control oftalmológico mañana martes a las 9:30 AM en el piso 2. No necesita hacer ningún pago previo ni abrir enlaces. Si desea reprogramar, llame usted mismo al teléfono fijo de su tarjeta médica."',
        correct_answer: 'SAFE',
        clue_highlight: 'No trae enlaces raros, no mete miedo ni pide claves ni dinero',
        explanation_calm:
          '¡Correcto! Un mensaje legítimo e informativo no te presiona con relojes en contra, no incluye enlaces sospechosos y nunca te pide claves ni pagos sorpresivos.',
      },
    ];
  }
}
