---
id: 3d0c
title: Todo lo que markdown puede hacer aquí
---

Todo lo de abajo se hizo con la barra de arriba de esta nota. Sin ajustes, sin extensiones. Selecciona texto y la barra actúa sobre él. Haz clic en una línea vacía y empieza algo nuevo.

## Palabras

Puedes poner una palabra en **negrita**, o en *cursiva*, o en ***ambas***. Puedes tacharla, ~~como esta~~. Puedes <u>subrayarla</u>. La letra pequeña va en <sub>subíndice</sub> y las potencias en <sup>superíndice</sup>.

El texto puede ser <span style="color: #e03131">rojo</span>, <span style="color: #1971c2">azul</span>, <span style="color: #2f9e44">verde</span> o cualquiera de nueve colores.

Puede ir ==resaltado en amarillo== o <mark style="background-color: rgba(64, 192, 87, 0.35)">en verde</mark>.

El botón **Aa** cambia el tamaño y la fuente. El texto puede ser <span style="font-size: 0.85em">pequeño</span>, normal o <span style="font-size: 1.6em">grande</span>. Puede ser <span style="font-family: ui-sans-serif, system-ui, sans-serif">liso</span>, <span style="font-family: ui-serif, Georgia, Cambria, serif">con serifa</span> o <span style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace">monoespaciado</span>.

## Dónde se colocan las palabras

<p style="text-align: center;">Este párrafo está centrado.</p>

<p style="text-align: right;">Este está empujado a la derecha.</p>

La alineación mueve un párrafo entero, nunca una sola palabra. Pon el cursor en el párrafo y usa el botón de alineación.

## Listas

- Un punto normal
- Otro
  - Pulsa Tab para meter una línea
    - Y otra vez

1. Un paso numerado
2. Un segundo paso
3. Inserta un paso donde sea y los números se corrigen solos

- [x] Una casilla que has marcado

- [ ] Casilla

  - [ ] Pulsa Tab para indentar una tarea

  - [ ] Marca la casilla y mira la animación

- [ ] Pulsa Mayús y Tab para reducir la indentación

## Tablas

| Región | Notas | Cuota |
| --- | :---: | ---: |
| Europa | 1.204 | 48 % |
| América | 902 | 36 % |
| Asia | 401 | 16 % |

La columna del medio está centrada y la última alineada a la derecha. Arrastra el borde de una columna para ensancharla.

## Avisos

Un aviso es una caja de color para algo que nadie debe pasar por alto.

> [!tip]+ Consejo
> Haz clic en el título de un aviso para plegarlo.

> [!warning]+ Advertencia
> Cada tipo tiene su color y su icono.

> [!danger]+ Peligro
> Hay nueve tipos. El menú **Insertar** los lista.

## Citas

> Una cita se separa del margen y lleva una línea de color a un lado.

## Código

El código conserva sus espacios y se colorea según el lenguaje.

```js
export function seal(note, key) {
  const nonce = randomBytes(24);
  return xchacha20poly1305(key, nonce).encrypt(note);
}
```

```python
def rolling_mean(values, window):
    return [sum(values[i:i + window]) / window
            for i in range(len(values) - window + 1)]
```

Un trozo corto de código dentro de una frase se ve así: `esto`.

## Matemáticas

Las matemáticas pueden ir dentro de una frase, como $a^2 + b^2 = c^2$, o en su propia línea:

$$i\hbar\frac{\partial}{\partial t}\Psi = \hat{H}\Psi$$

## Imágenes

![El monte Fuji tras las flores de cerezo.](/onboarding/fuji.webp){width=50 align=center}

Arrastra una imagen a una nota, o pégala. Haz clic en ella una vez para cambiar su tamaño, o para moverla a la izquierda, al centro o a la derecha. La de arriba está a media anchura y centrada.

## Enlaces

Hay dos tipos, y se ven distintos a propósito.

- Un enlace web abre un sitio: [privacynotes.app](https://privacynotes.app/es)
- Un enlace de nota abre otra de tus notas: [[Cómo se protegen tus notas]]

Los dos tienen botón en la barra. La cadena hace un enlace web. El de al lado lista tus notas y eliges la que quieres.

---

*Si ya escribes markdown, escríbelo y se formatea sobre la marcha. Para ver el texto en bruto de cualquier nota, pulsa **Ver markdown** abajo a la derecha de esta nota.*
