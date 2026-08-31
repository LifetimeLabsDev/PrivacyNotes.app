---
id: 5ec1
title: Como suas notas são protegidas
---

> [!info]- Cada nota é criptografada no seu dispositivo, antes de ser guardada em qualquer lugar.
> &nbsp;

![A tabela de notas no nosso banco de dados real. Cada nota é um bloco longo de texto ilegível.](/onboarding/database.webp)

Aquele é o nosso banco de dados de verdade em Zurique, não um desenho. Sua nota vai para a coluna `ciphertext`. Bytes criptografados é tudo o que guardamos, qualquer que seja a opção escolhida abaixo.

## O que acontece quando você escreve uma nota

1. Sua frase de 12 palavras vira uma chave. Isso acontece no seu dispositivo.
2. A nota é criptografada com essa chave, no seu dispositivo. É assim que ela fica guardada no seu próprio disco, e é assim que ela viaja até nós.
3. Recebemos a nota criptografada e guardamos. A imagem acima é a cara disso.
4. Qualquer dispositivo com a mesma frase cria a mesma chave e abre a nota.

## Quem tem a sua chave

Todas as opções mantêm suas notas criptografadas de ponta a ponta. Elas diferem em onde a sua frase fica.

| Opção | Onde sua frase fica | O que isso te dá |
| --- | --- | --- |
| **Login, chave conosco** | No nosso servidor, criptografada | Um dispositivo novo entra só com essa conta |
| **Login, chave no seu dispositivo** | Com você, em nenhum outro lugar | Entre com Google, Apple ou GitHub e continue com a chave |
| **Só a frase, sem login** | Com você, em nenhum outro lugar | Sem e-mail, sem nome, sem conta nenhuma |

Nas duas de baixo não conseguiríamos ler uma nota nem se fôssemos obrigados. A primeira troca isso por comodidade: sua frase fica no nosso servidor sob uma chave nossa, então um dispositivo novo não precisa de nada além da sua conta. Se o nosso servidor fosse invadido algum dia, essa chave poderia ficar exposta.

Você não fica preso à escolha que fez. Mude em **Configurações > Segurança > Sua frase**.

> [!warning] Tenha sua própria cópia da frase
> Sua frase abre suas notas. Se você perder, ninguém recupera, nós inclusive. <span style="color: #e03131">Escreva no papel hoje.</span>

## Confira você mesmo

[Instruções detalhadas de verificação no GitHub](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md)

- [ ] Abra a aba de rede do seu navegador e depois edite uma nota. Veja o que chega para nós: um bloco de texto ilegível.
- [ ] Leia o código da criptografia. Ele é público e curto o bastante para terminar de uma vez.

| O quê | Onde |
| --- | --- |
| A criptografia em si | [crypto.ts](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/crypto/crypto.ts) |
| A estrutura do banco de dados | [schema.sql](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/schema/schema.sql) |
| O que um atacante pode e não pode fazer | [THREAT_MODEL.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/THREAT_MODEL.md) |
| Como relatar uma falha | [SECURITY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/SECURITY.md) |

> [!info] Uma fechadura cobre tudo
> Notas, entradas de diário, favoritos, itens do cofre e anexos são criptografados do mesmo jeito. [[A mudança]] mostra como trazer cada um deles.
