# Operational UI Redesign Design

**Status:** Approved for specification review

## Objective

Upgrade the promotion application into a consistent light operations cockpit, delivered in this order: Home, FIFO, Profile, CSKH, and Quote Builder. The redesign improves hierarchy, scanability, responsive behavior, and accessibility without changing routes, permissions, backend contracts, or established JavaScript selectors.

## Scope And Delivery Boundaries

The redesign is one shared visual system delivered through five independently testable page waves:

1. Shared visual foundation and Home.
2. FIFO checking.
3. Profile and performance.
4. Customer care.
5. Quote Builder.

Each wave may modify its target EJS view and a namespaced stylesheet only. Existing server routes, API payloads, form names, element IDs used by scripts, role checks, and export/print behavior remain compatible. No feature, data-schema, permission, or workflow redesign is part of this effort.

## Shared Visual Foundation

### Visual Direction

Use a light, data-dense operations cockpit rather than a marketing dashboard. The background is a cool blue-gray field, panels are white, text is deep blue-black, and spacing follows an 8px scale. Blue identifies navigation and primary actions; emerald identifies healthy or completed states; amber identifies attention; red is reserved for errors, expired information, destructive actions, or high-risk conditions.

The interface uses a restrained shadow, a one-pixel low-contrast border, 12-16px corner radii, and visible keyboard focus rings. Status is communicated through both color and labels/icons, never color alone.

### Layout Contract

Every redesigned page uses these visual regions while preserving its existing document structure where JavaScript requires it:

- **Page header / command bar:** page title, concise purpose, contextual summary metrics, and primary action(s).
- **Control surface:** a contained filter/search area. Frequently used controls are visible; secondary filters use a collapsible or grouped treatment only where existing behavior permits.
- **Work surface:** tables, results, forms, charts, or builders with a clear primary reading order.
- **Supporting information:** history, notes, detail, or explanation rendered after the primary action area rather than competing with it.

Global navigation remains in `views/partials/header.ejs`; it gets visual refinement only, with all menu visibility and role conditions preserved.

### Responsive And Accessibility Rules

- Desktop starts at 1024px. Tablet uses 768-1023px. Mobile is below 768px.
- Tables keep semantic table markup. On narrow screens, containers scroll horizontally only when an equivalent compact-row view cannot safely be produced without altering behavior.
- Touch targets are at least 40px square where practical. Text controls maintain readable 14px minimum body text.
- Inputs retain explicit labels or accessible names. Buttons use real text or an `aria-label` where icon-only.
- Respect `prefers-reduced-motion`; loading/reveal effects are brief and nonessential.

### Implementation Boundary

Use a small shared token layer in `public/css/style.css`, then append page-scoped style blocks using root classes or page-specific IDs. Avoid broad selector rewrites against legacy `.dash-card`, `.btn`, table, or form classes because they are shared by unrelated screens. Existing inline page styles are migrated only when doing so is necessary for the target page and can be isolated safely.

## Wave 1: Home

### User Outcome

Users immediately see the most useful promotion context and can move to an SKU or promotion workflow without scanning an oversized wall of cards.

### Structure

- Add a compact command header around the existing home title/search behavior.
- Present the featured-promotion region as ranked horizontal entries with an explicit saving/value signal, expiry state, applicable product/category context, and a single direct action.
- Keep existing filter metadata, list IDs, API calls, pagination, and promotion links intact.
- Use progressive density: a richer desktop row, then a compact stacked treatment below 620px.

### Acceptance Criteria

- Current featured-promotion filtering and click-through work unchanged.
- No promotion card introduces horizontal overflow at 320px viewport width.
- The first visible promotion explains what it is, its value, expiry state, and destination without relying on hover.

## Wave 2: FIFO Checking

### User Outcome

Warehouse users can scan/search serials and recognize inventory age, location, and next action quickly under operational pressure.

### Structure

- Group scan/search controls as the dominant command bar; retain all current input IDs and scan/search/reset handlers.
- Separate quick toggles from categorical filters so the initial scan path stays uncluttered.
- Reframe result data with a hierarchy of SKU identity, location, serial status, and age. FIFO aging uses semantic labels and a compact indicator, not color alone.
- Present history and scan help as support panels after the primary results area.

### Acceptance Criteria

- Barcode/scanner focus, Enter behavior, search, reset, existing filters, and result rendering are unchanged.
- A user can identify the next serial to process and any stale inventory from the results without opening details.
- Empty, loading, and error states have distinct, actionable copy.

## Wave 3: Profile And Performance

### User Outcome

Staff see their identity, selected date range, KPI direction, charts, and performance records in a predictable reading sequence.

### Structure

- Retain the profile identity card but reduce decorative gradients and improve contrast.
- Place role-appropriate KPIs directly below the page command header. Do not expose metrics currently gated by role.
- Use consistent chart containers with clear titles, date/context labels, and stable heights.
- Put filters immediately before the data table they affect; retain all existing export/table behavior.

### Acceptance Criteria

- Staff-role metric hiding remains unchanged.
- Charts and tables remain usable at desktop, tablet, and mobile widths.
- Profile data, date filtering, and existing API error behavior are unchanged.

## Wave 4: Customer Care

### User Outcome

CSKH staff can triage queue volume, SLA, customer feedback, and assigned work without losing context in a dense table.

### Structure

- Place operational summary metrics above the queue: open workload, SLA/overdue attention, store rating, and technician rating where the page already provides those values.
- Use a dedicated queue control surface for filtering, search, and primary actions, retaining all existing request/form interfaces.
- Tighten data columns. Ratings display as left-aligned number plus star icon, capped at 5 and without repeated star strings. Customer feedback wraps vertically within a bounded column rather than widening the table.
- Use a detail/support drawer or current detail mechanism for long history and feedback; do not discard any displayed data.

### Acceptance Criteria

- Existing queue filters, assignment/actions, ratings, report statistics, and role constraints still work.
- Rating columns remain compact while rating values are readable and accessible.
- Long customer feedback wraps and remains available without forcing whole-table horizontal expansion.

## Wave 5: Quote Builder

### User Outcome

Users can find products, configure a quote, understand totals, and export/print without losing their working context.

### Structure

- Preserve the two-workspace model: product discovery on the left and the quote configuration/summary on the right.
- Make the quote summary sticky only within a safe viewport/container boundary, keeping current buttons, form names, ordering controls, print preview, Excel/PDF export, and calculation DOM contracts unchanged.
- Separate product search/filter controls from product results, and use an obvious selected-state for items added to the quote.
- Make price breakdown, discount, delivery, notes, and export actions visually ordered by decision importance rather than raw source order.

### Acceptance Criteria

- Add/remove/reorder products, totals, previews, PDF, Excel, print, and submit functions continue to work.
- The primary quote total and export action remain visible on normal laptop layouts without concealing editable content.
- On mobile/tablet, panels stack in a controlled order and do not rely on a fixed sidebar.

## Data Flow And Compatibility

All pages continue using their existing server-rendered EJS variables and browser-side API calls. The redesign must not rename or delete IDs, `data-*` attributes, form control names, script event targets, API endpoints, backend field names, server-side role checks, or link destinations. New visual wrappers may be added only around these contracts.

## Error, Empty, And Loading States

Every target work surface needs a consistent visual treatment for:

- **Loading:** an in-place skeleton or textual progress indicator; never a layout jump that moves active controls.
- **Empty:** short explanation plus the relevant reset/search action.
- **Error:** readable failure message, retry path when one already exists, and no loss of entered filter values.

Client-side error handling remains in current scripts. This scope adds presentation only unless a missing state prevents an existing error from being visible.

## Verification Strategy

- Compile every changed EJS template with the project renderer/compiler available in the repository.
- Run `node --check server.js` after server-adjacent changes; UI-only waves do not modify server behavior by default.
- Run the project test/lint scripts defined in `package.json`, if available, after each wave.
- Perform manual browser checks at 1440px, 1024px, 768px, and 375px for each target route, using an authenticated local session supplied by the user when access is required.
- Test keyboard navigation for primary filters, actions, modal triggers, and exports. Confirm visible focus treatment.
- Confirm browser console has no new JavaScript errors while exercising existing primary workflows.

## Non-Goals

- No changes to authentication, authorization, user role rules, BigQuery/Google Sheets integration, APIs, database tables, or routes.
- No new component framework, CSS framework, charting library, or design dependency.
- No backend refactor outside a minimal adjustment needed to preserve existing UI behavior.
- No replacement of existing quote output template/business calculations.
