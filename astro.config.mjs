// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
// The "Write-ups" group is filled with one sub-group per CTF by src/routeData.ts,
// from the scripts in src/writeups/.
const sidebar = [{ label: 'Write-ups', items: [{ label: 'Search', link: '/writeups/' }] }];

// https://astro.build/config
export default defineConfig({
	site: 'https://0xarctos.github.io',
	integrations: [
		starlight({
			title: '0xarctos',
			description: 'CTF write-ups - focus pwn and reverse',
			logo: { src: './src/assets/avatar.jpg', alt: '0xarctos avatar' },
			favicon: '/favicon.jpg',
			customCss: ['./src/styles/custom.css'],
			components: {
				ThemeProvider: './src/components/ThemeProvider.astro',
				ThemeSelect: './src/components/ThemeSelect.astro',
			},
			locales: { root: { label: 'English', lang: 'en' } },
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/0xarctos' }],
			lastUpdated: true,
			sidebar,
			routeMiddleware: './src/routeData.ts',
			// GoatCounter analytics (ignores localhost, so dev visits are not counted)
			head: [
				{
					tag: 'script',
					attrs: {
						src: 'https://gc.zgo.at/count.js',
						'data-goatcounter': 'https://0xarctos.goatcounter.com/count',
						async: true,
					},
				},
			],
		}),
	],
});
