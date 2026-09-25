---
id: 5ec1
title: Cómo se protegen tus notas
---

> [!info]- Cada nota se cifra en tu dispositivo, antes de guardarse en ningún sitio.
> &nbsp;

![La tabla de notas de nuestra base de datos real. Cada nota es un bloque largo de texto ilegible.](/onboarding/database.webp)

Esa es nuestra base de datos real en Zúrich, no un dibujo. Tu nota va en la columna `ciphertext`. Bytes cifrados es todo lo que guardamos, elijas la opción que elijas más abajo.

## Qué ocurre cuando escribes una nota

1. Tu frase de 12 palabras se convierte en una clave. Eso pasa en tu dispositivo.
2. La nota se cifra con esa clave, en tu dispositivo. Así se guarda en tu propio disco, y así viaja hasta nosotros.
3. Recibimos la nota cifrada y la guardamos. La imagen de arriba es el aspecto que tiene.
4. Cualquier dispositivo con la misma frase crea la misma clave y abre la nota.

## Quién tiene tu clave

Todas las opciones mantienen tus notas cifradas en tu dispositivo. Se diferencian en dónde vive tu frase.

| Opción | Dónde vive tu frase | Qué te da |
| --- | --- | --- |
| **Inicio de sesión, clave con nosotros** | En nuestro servidor, cifrada | Un dispositivo nuevo entra solo con esa cuenta |
| **Inicio de sesión, clave en tu dispositivo** | Contigo, en ningún otro sitio | Entra con Google, Apple o GitHub y conserva la clave |
| **Solo frase, sin inicio de sesión** | Contigo, en ningún otro sitio | Sin correo, sin nombre, sin cuenta |

Con las dos últimas no podríamos leer una nota ni aunque nos obligaran. La primera cambia eso por comodidad: tu frase está en nuestro servidor bajo una clave nuestra, así que un dispositivo nuevo no necesita nada más que tu cuenta. Si alguna vez atacaran nuestro servidor, esa clave podría quedar expuesta.

¿Has iniciado sesión con Google, Apple o GitHub? Puedes cambiar entre las dos primeras más adelante, en **Ajustes > Seguridad > Tu frase**. Con una cuenta de solo frase, la frase siempre se queda contigo.

> [!warning] Guarda tu propia copia de la frase
> Tu frase abre tus notas. Si la pierdes, nadie puede recuperarla, nosotros incluidos. <span style="color: #e03131">Escríbela en papel hoy.</span>

## Compruébalo tú mismo

[Instrucciones detalladas de verificación en GitHub](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md)

- [ ] Abre la pestaña de red de tu navegador y luego edita una nota. Mira lo que recibimos: un bloque de texto ilegible.
- [ ] Lee el código de cifrado. Es público y bastante corto como para leerlo de una sentada.

| Qué | Dónde |
| --- | --- |
| El cifrado en sí | [crypto.ts](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/crypto/crypto.ts) |
| Qué recibe nuestro servidor | [VERIFY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md#tier-1-one-minute-no-tools) |
| Qué puede y qué no puede hacer un atacante | [THREAT_MODEL.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/THREAT_MODEL.md) |
| Cómo informar de un fallo | [SECURITY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/SECURITY.md) |

> [!info] Una sola cerradura lo cubre todo
> Notas, entradas de diario, marcadores, elementos de la bóveda y archivos adjuntos se cifran igual. [[La mudanza]] muestra cómo traer cada uno.
