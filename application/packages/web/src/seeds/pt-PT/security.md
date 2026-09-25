---
id: 5ec1
title: Como as tuas notas estão protegidas
---

> [!info]- Cada nota é cifrada no teu dispositivo, antes de ser guardada em qualquer sítio.
> &nbsp;

![A tabela de notas na nossa base de dados real. Cada nota é um bloco longo de texto ilegível.](/onboarding/database.webp)

Aquela é a nossa base de dados a sério em Zurique, não um desenho. A tua nota vai para a coluna `ciphertext`. Bytes cifrados é tudo o que guardamos, escolhas tu a opção que escolheres abaixo.

## O que acontece quando escreves uma nota

1. A tua frase de 12 palavras torna-se uma chave. Isso acontece no teu dispositivo.
2. A nota é cifrada com essa chave, no teu dispositivo. É assim que fica guardada no teu próprio disco, e é assim que viaja até nós.
3. Recebemos a nota cifrada e guardamo-la. A imagem acima é o aspeto que isso tem.
4. Qualquer dispositivo com a mesma frase cria a mesma chave e abre a nota.

## Quem tem a tua chave

Todas as opções mantêm as tuas notas cifradas no teu dispositivo. Diferem em onde vive a tua frase.

| Opção | Onde vive a tua frase | O que te dá |
| --- | --- | --- |
| **Sessão iniciada, chave connosco** | No nosso servidor, cifrada | Um dispositivo novo entra só com essa conta |
| **Sessão iniciada, chave no teu dispositivo** | Contigo, em mais lado nenhum | Entra com Google, Apple ou GitHub e continua a ter a chave |
| **Só a frase, sem início de sessão** | Contigo, em mais lado nenhum | Sem email, sem nome, sem conta nenhuma |

Nas duas de baixo não conseguiríamos ler uma nota nem que nos obrigassem. A primeira troca isso por comodidade: a tua frase fica no nosso servidor sob uma chave nossa, por isso um dispositivo novo não precisa de mais nada além da tua conta. Se o nosso servidor fosse alguma vez comprometido, essa chave podia ficar exposta.

Iniciaste sessão com Google, Apple ou GitHub? Podes alternar entre as duas primeiras mais tarde, em **Definições > Segurança > A tua frase**. Com uma conta só de frase, a frase fica sempre contigo.

> [!warning] Guarda a tua própria cópia da frase
> A tua frase abre as tuas notas. Se a perderes, ninguém a recupera por ti, nós incluídos. <span style="color: #e03131">Escreve-a em papel hoje.</span>

## Confirma tu mesmo

[Instruções detalhadas de verificação no GitHub](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md)

- [ ] Abre o separador de rede do teu navegador e edita depois uma nota. Vê o que nos chega: um bloco de texto ilegível.
- [ ] Lê o código da cifra. É público e curto o suficiente para acabar de uma vez.

| O quê | Onde |
| --- | --- |
| A cifra em si | [crypto.ts](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/crypto/crypto.ts) |
| O que o nosso servidor recebe | [VERIFY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md#tier-1-one-minute-no-tools) |
| O que um atacante pode e não pode fazer | [THREAT_MODEL.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/THREAT_MODEL.md) |
| Como comunicar uma falha | [SECURITY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/SECURITY.md) |

> [!info] Uma só fechadura cobre tudo
> Notas, entradas de diário, marcadores, itens do cofre e anexos são cifrados da mesma maneira. [[A mudança]] mostra como trazer cada um deles.
