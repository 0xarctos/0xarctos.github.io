import { OGImageRoute } from 'astro-og-canvas';
import { getCollection } from 'astro:content';

// Generates one social-embed banner per write-up at /og/<ctf-slug>/<challenge>.png.
// The challenge pages reference these as their og:image, so pasting a write-up
// URL on Discord/Slack shows a branded card (title + CTF + tags + avatar).
const writeups = await getCollection('writeups');
const pages = Object.fromEntries(writeups.map((entry) => [entry.id, entry.data]));

export const { getStaticPaths, GET } = await OGImageRoute({
	pages,
	getImageOptions: (_id, data) => ({
		title: data.title,
		description: `${data.ctf}  /  ${data.category}  /  ${data.tags.join(', ')}`,
		logo: { path: './src/assets/avatar.jpg', size: [150] },
		bgGradient: [
			[11, 13, 20],
			[23, 27, 38],
		],
		border: { color: [56, 189, 248], width: 16, side: 'inline-start' },
		padding: 70,
		font: {
			title: { color: [237, 242, 255], size: 68, weight: 'Bold', families: ['DejaVu Sans'] },
			description: { color: [148, 163, 184], size: 30, lineHeight: 1.4, families: ['DejaVu Sans'] },
		},
		fonts: ['./src/assets/fonts/DejaVuSans.ttf', './src/assets/fonts/DejaVuSans-Bold.ttf'],
	}),
});
