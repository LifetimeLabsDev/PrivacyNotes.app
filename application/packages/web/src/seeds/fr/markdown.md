---
id: 3d0c
title: Tout ce que markdown sait faire ici
---

Tout ce qui suit a été fait avec la barre en haut de cette note. Aucun réglage, aucune extension. Sélectionne du texte et la barre agit dessus. Clique dans une ligne vide et elle commence quelque chose de neuf.

## Les mots

Tu peux mettre un mot en **gras**, en *italique*, ou ***les deux***. Tu peux le barrer, ~~comme celui-ci~~. Tu peux le <u>souligner</u>. Les petits caractères vont en <sub>indice</sub> et les puissances en <sup>exposant</sup>.

Le texte peut être <span style="color: #e03131">rouge</span>, <span style="color: #1971c2">bleu</span>, <span style="color: #2f9e44">vert</span> ou de l'une des neuf couleurs.

Il peut être ==surligné en jaune== ou <mark style="background-color: rgba(64, 192, 87, 0.35)">en vert</mark>.

Le bouton **Aa** change la taille et la police. Le texte peut être <span style="font-size: 0.85em">petit</span>, normal ou <span style="font-size: 1.6em">grand</span>. Il peut être <span style="font-family: ui-sans-serif, system-ui, sans-serif">simple</span>, <span style="font-family: ui-serif, Georgia, Cambria, serif">avec empattements</span> ou <span style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace">à chasse fixe</span>.

## Où se placent les mots

<p style="text-align: center;">Ce paragraphe est centré.</p>

<p style="text-align: right;">Celui-ci est poussé à droite.</p>

L'alignement déplace un paragraphe entier, jamais un mot seul. Mets le curseur dans le paragraphe et utilise le bouton d'alignement.

## Listes

- Une puce simple
- Une autre
  - Appuie sur Tab pour décaler une ligne
    - Et encore une fois

1. Une étape numérotée
2. Une deuxième étape
3. Insère une étape n'importe où et les numéros se corrigent tout seuls

- [x] Une case que tu as cochée

- [ ] Case

  - [ ] Appuie sur Tab pour décaler une tâche

  - [ ] Coche la case et regarde l'animation

- [ ] Appuie sur Maj et Tab pour réduire le décalage

## Tableaux

| Région | Notes | Part |
| --- | :---: | ---: |
| Europe | 1 204 | 48 % |
| Amériques | 902 | 36 % |
| Asie | 401 | 16 % |

La colonne du milieu est centrée et la dernière alignée à droite. Fais glisser le bord d'une colonne pour l'élargir.

## Encadrés

Un encadré est une boîte colorée pour ce qu'il ne faut surtout pas rater.

> [!tip]+ Astuce
> Clique sur le titre d'un encadré pour le replier.

> [!warning]+ Avertissement
> Chaque type a sa couleur et son icône.

> [!danger]+ Danger
> Il y en a neuf. Le menu **Insérer** les liste.

## Citations

> Une citation se décale de la marge et prend un trait coloré sur le côté.

## Code

Le code garde ses espaces et se colore selon le langage.

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

Un bout de code court au milieu d'une phrase ressemble plutôt à `ceci`.

## Maths

Les maths peuvent tenir dans une phrase, comme $a^2 + b^2 = c^2$, ou occuper leur propre ligne :

$$i\hbar\frac{\partial}{\partial t}\Psi = \hat{H}\Psi$$

## Images

![Le mont Fuji derrière des fleurs de cerisier.](/onboarding/fuji.webp){width=50 align=center}

Fais glisser une image dans une note, ou colle-la. Clique dessus une fois pour changer sa taille, ou pour la placer à gauche, au centre ou à droite. Celle du dessus est à mi-largeur et centrée.

## Liens

Il y en a deux sortes, et elles ne se ressemblent pas, exprès.

- Un lien web ouvre un site : [privacynotes.app](https://privacynotes.app/fr)
- Un lien de note ouvre une autre de tes notes : [[Comment tes notes sont protégées]]

Les deux ont un bouton dans la barre. La chaîne fait un lien web. Les crochets font un lien de note : ils listent tes notes et tu choisis celle que tu veux. Taper `[[` fait la même chose.

---

*Si tu écris déjà en markdown, tape-le et la mise en forme suit. Pour voir le texte brut derrière n'importe quelle note, clique sur **Afficher le markdown** en bas à droite de cette note.*
