---
id: 3d0c
title: Tudo o que o markdown faz aqui
---

Tudo o que está abaixo foi feito com a barra no topo desta nota. Sem definições, sem extensões. Seleciona texto e a barra atua sobre ele. Clica numa linha vazia e começa algo novo.

## Palavras

Podes pôr uma palavra a **negrito**, ou em *itálico*, ou ***nos dois***. Podes riscá-la, ~~como esta~~. Podes <u>sublinhá-la</u>. As letras pequenas vão em <sub>índice</sub> e as potências em <sup>expoente</sup>.

O texto pode ser <span style="color: #e03131">vermelho</span>, <span style="color: #1971c2">azul</span>, <span style="color: #2f9e44">verde</span> ou uma de nove cores.

Pode estar ==realçado a amarelo== ou <mark style="background-color: rgba(64, 192, 87, 0.35)">a verde</mark>.

O botão **Aa** muda o tamanho e o tipo de letra. O texto pode ser <span style="font-size: 0.85em">pequeno</span>, normal ou <span style="font-size: 1.6em">grande</span>. Pode ser <span style="font-family: ui-sans-serif, system-ui, sans-serif">simples</span>, <span style="font-family: ui-serif, Georgia, Cambria, serif">com serifa</span> ou <span style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace">monoespaçado</span>.

## Onde ficam as palavras

<p style="text-align: center;">Este parágrafo está ao centro.</p>

<p style="text-align: right;">Este está empurrado para a direita.</p>

O alinhamento move um parágrafo inteiro, nunca uma palavra só. Põe o cursor no parágrafo e usa o botão de alinhamento.

## Listas

- Um ponto simples
- Outro
  - Carrega em Tab para avançar uma linha
    - E outra vez

1. Um passo numerado
2. Um segundo passo
3. Insere um passo onde quiseres e os números corrigem-se sozinhos

- [x] Uma caixa que assinalaste

- [ ] Caixa

  - [ ] Carrega em Tab para avançar uma tarefa

  - [ ] Assinala a caixa e vê a animação

- [ ] Carrega em Shift e Tab para recuar

## Tabelas

| Região | Notas | Quota |
| --- | :---: | ---: |
| Europa | 1204 | 48 % |
| Américas | 902 | 36 % |
| Ásia | 401 | 16 % |

A coluna do meio está ao centro e a última alinhada à direita. Arrasta a borda de uma coluna para a alargar.

## Avisos

Um aviso é uma caixa colorida para algo que ninguém deve perder de vista.

> [!tip]+ Dica
> Clica no título de um aviso para o fechar.

> [!warning]+ Atenção
> Cada tipo tem a sua cor e o seu ícone.

> [!danger]+ Perigo
> Há nove tipos. O menu **Inserir** lista-os.

## Citações

> Uma citação recua da margem e ganha uma linha colorida ao lado.

## Notas de rodapé

Uma nota de rodapé tira do texto uma fonte ou um aparte.[^1] Escreve `[^1]` depois de uma palavra, ou escolhe **Nota de rodapé** no menu **Inserir**. Clica no número pequeno para ires à nota.

## Código

O código mantém o espaçamento e é colorido conforme a linguagem. O nome no topo de um bloco é a sua linguagem: clica nele para escolher outra.

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

Um bloco longo abre recolhido, para que o resto da nota fique perto. O botão por baixo mostra todas as linhas.

```js
const WORDS_PER_MINUTE = 200;

export function readingStats(markdown) {
  const text = markdown
    .replace(/!\[[^\]]*\]\([^)]*\)/g, ' ')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[#*_~`>|-]/g, ' ');

  const words = text.split(/\s+/).filter(Boolean);
  const headings = markdown.match(/^#{1,6} /gm) ?? [];
  const tasks = markdown.match(/^\s*- \[[ x]\] /gm) ?? [];
  const done = tasks.filter((task) => task.includes('[x]'));

  return {
    words: words.length,
    minutes: Math.max(1, Math.round(words.length / WORDS_PER_MINUTE)),
    headings: headings.length,
    tasks: tasks.length,
    done: done.length,
  };
}

export function summary(stats) {
  const parts = [`${stats.words} words`, `${stats.minutes} min read`];
  if (stats.headings > 0) {
    parts.push(`${stats.headings} sections`);
  }
  if (stats.tasks > 0) {
    parts.push(`${stats.done} of ${stats.tasks} tasks done`);
  }
  return parts.join(' · ');
}

export function isLongRead(stats) {
  return stats.minutes >= 10;
}
```

Um bocado curto de código dentro de uma frase aparece assim: `isto`.

## Matemática

A matemática pode ficar dentro de uma frase, como $a^2 + b^2 = c^2$, ou numa linha só dela:

$$i\hbar\frac{\partial}{\partial t}\Psi = \hat{H}\Psi$$

## Imagens

![O monte Fuji atrás das flores de cerejeira.](/onboarding/fuji.webp){width=50 align=center}

Arrasta uma imagem para uma nota, ou cola-a. Clica nela uma vez para mudar o tamanho, ou para a pôr à esquerda, ao centro ou à direita. A de cima está a meia largura e ao centro.

## Ligações

Há dois tipos, e são diferentes de propósito.

- Uma ligação web abre um site: [privacynotes.app](https://privacynotes.app/pt)
- Uma ligação entre notas abre outra nota tua: [[Como as tuas notas estão protegidas]]

Os dois têm botão na barra. A corrente faz uma ligação web. Os parênteses retos fazem uma ligação entre notas: listam as tuas notas e escolhes a que queres. Escrever `[[` faz o mesmo.

Uma ligação entre notas também pode abrir uma nota num dos seus títulos. Escreve um `#` depois do título da nota e escolhe o título da secção: [[Como as tuas notas estão protegidas#Quem tem a tua chave]] abre essa nota na secção sobre a chave. O ícone de ligação num título da estrutura copia essa ligação por ti.

---

*Se já escreves markdown, escreve-o e ele formata-se à medida. Para veres o texto em bruto por trás de qualquer nota, clica em **Ver markdown** em baixo à direita nesta nota.*

[^1]: Esta é a nota. A seta ao lado leva-te de volta para cima.
