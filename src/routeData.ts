import { defineRouteMiddleware } from '@astrojs/starlight/route-data';
import { getCollection } from 'astro:content';
import { categoryVariant } from './lib/writeups';

type SidebarEntry = App.Locals['starlightRoute']['sidebar'][number];

// Fills the "Write-ups" sidebar group with one sub-group per CTF, built from the scripts.
export const onRequest = defineRouteMiddleware(async (context) => {
	const route = context.locals.starlightRoute;
	const group = route.sidebar.find((e) => e.type === 'group' && e.label === 'Write-ups');
	if (!group || group.type !== 'group') return;

	const current = context.url.pathname.replace(/\/?$/, '/');
	const byCtf = new Map<string, SidebarEntry[]>();
	for (const { id, data } of await getCollection('writeups')) {
		const href = `/writeups/${id}/`;
		const links = byCtf.get(data.ctf) ?? [];
		links.push({
			type: 'link',
			label: data.title,
			href,
			isCurrent: href === current,
			badge: { text: data.category, variant: categoryVariant(data.category) },
			attrs: {},
		});
		byCtf.set(data.ctf, links);
	}

	for (const [ctf, links] of [...byCtf].sort((a, b) => a[0].localeCompare(b[0]))) {
		links.sort((a, b) => a.label.localeCompare(b.label));
		group.entries.push({
			type: 'group',
			label: ctf,
			entries: links,
			collapsed: !links.some((l) => l.type === 'link' && l.isCurrent),
			badge: undefined,
		});
	}
});
