---
id: 3d0c
title: Tudo o que o markdown faz aqui
---

Tudo o que está abaixo foi feito com a barra no topo desta nota. Sem configurações, sem plugins. Selecione um texto e a barra age sobre ele. Clique em uma linha vazia e ela começa algo novo.

## Palavras

Você pode deixar uma palavra em **negrito**, ou em *itálico*, ou ***nos dois***. Pode riscar, ~~como esta~~. Pode <u>sublinhar</u>. Letras pequenas vão em <sub>subscrito</sub> e potências em <sup>sobrescrito</sup>.

O texto pode ser <span style="color: #e03131">vermelho</span>, <span style="color: #1971c2">azul</span>, <span style="color: #2f9e44">verde</span> ou uma de nove cores.

Pode ficar ==destacado em amarelo== ou <mark style="background-color: rgba(64, 192, 87, 0.35)">em verde</mark>.

O botão **Aa** muda o tamanho e a fonte. O texto pode ser <span style="font-size: 0.85em">pequeno</span>, normal ou <span style="font-size: 1.6em">grande</span>. Pode ser <span style="font-family: ui-sans-serif, system-ui, sans-serif">simples</span>, <span style="font-family: ui-serif, Georgia, Cambria, serif">com serifa</span> ou <span style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace">monoespaçado</span>.

## Onde as palavras ficam

<p style="text-align: center;">Este parágrafo está centralizado.</p>

<p style="text-align: right;">Este está empurrado para a direita.</p>

O alinhamento move um parágrafo inteiro, nunca uma palavra sozinha. Ponha o cursor no parágrafo e use o botão de alinhamento.

## Listas

- Um item simples
- Outro
  - Aperte Tab para recuar uma linha
    - E de novo

1. Um passo numerado
2. Um segundo passo
3. Insira um passo em qualquer lugar e os números se corrigem sozinhos

- [x] Uma caixa que você marcou

- [ ] Caixa

  - [ ] Aperte Tab para recuar uma tarefa

  - [ ] Marque a caixa e veja a animação

- [ ] Aperte Shift e Tab para diminuir o recuo

## Tabelas

| Região | Notas | Fatia |
| --- | :---: | ---: |
| Europa | 1.204 | 48 % |
| Américas | 902 | 36 % |
| Ásia | 401 | 16 % |

A coluna do meio está centralizada e a última alinhada à direita. Arraste a borda de uma coluna para deixá-la mais larga.

## Avisos

Um aviso é uma caixa colorida para algo que ninguém pode deixar passar.

> [!tip]+ Dica
> Clique no título de um aviso para fechá-lo.

> [!warning]+ Atenção
> Cada tipo tem sua cor e seu ícone.

> [!danger]+ Perigo
> São nove tipos. O menu **Inserir** lista todos.

## Citações

> Uma citação recua da margem e ganha uma linha colorida na lateral.

## Notas de rodapé

Uma nota de rodapé tira do texto uma fonte ou um comentário.[^1] Digite `[^1]` depois de uma palavra, ou escolha **Nota de rodapé** no menu **Inserir**. Clique no número pequeno para ir até a nota.

## Código

O código mantém o espaçamento e ganha cor conforme a linguagem. O nome no topo de um bloco é a linguagem dele: clique nele para escolher outra.

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

Um bloco longo abre recolhido, para que o resto da nota fique perto. O botão embaixo mostra todas as linhas.

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

Um pedaço curto de código dentro de uma frase aparece assim: `isto`.

## Matemática

A matemática pode ficar dentro de uma frase, como $a^2 + b^2 = c^2$, ou em uma linha só dela:

$$i\hbar\frac{\partial}{\partial t}\Psi = \hat{H}\Psi$$

## Imagens

![O monte Fuji atrás das flores de cerejeira.](/onboarding/fuji.webp){width=50 align=center}

Arraste uma imagem para dentro de uma nota, ou cole. Clique uma vez nela para mudar o tamanho, ou para movê-la à esquerda, ao centro ou à direita. A de cima está com metade da largura e centralizada.

## Links

São dois tipos, e eles são diferentes de propósito.

- Um link da web abre um site: [privacynotes.app](https://privacynotes.app/br)
- Um link entre notas abre outra nota sua: [[Como suas notas são protegidas]]

Os dois têm botão na barra. A corrente faz um link da web. Os colchetes fazem um link entre notas: listam suas notas e você escolhe qual quer. Digitar `[[` faz a mesma coisa.

Um link entre notas não precisa mostrar o título da nota. Digite o título, uma barra vertical e as palavras que você quer na página: [[Como suas notas são protegidas|estas palavras]] abrem essa nota.

Um link entre notas também pode abrir uma nota em um dos títulos dela. Digite um `#` depois do título da nota e escolha o título da seção: [[Como suas notas são protegidas#Quem tem a sua chave]] abre essa nota na seção sobre a chave. O ícone de link em um título da estrutura copia esse link para você.

---

*Se você já escreve markdown, digite e ele se formata na hora. Para ver o texto puro por trás de qualquer nota, clique em **Ver markdown** no canto inferior direito desta nota.*

[^1]: Esta é a nota. A seta ao lado leva você de volta para cima.
