import { useId, useState } from "react";

type RepositoryOption<T extends string | number> = { id: T; name: string; detail?: string };
const PAGE_SIZE = 50;

/** Filtering/paging changes presentation only; the caller owns the exact selection. */
export function ConnectorRepositoryPicker<T extends string | number>({
  label = "Select repositories for Denali analysis", items, selected, onChange, disabled = false,
}: {
  label?: string;
  items: readonly RepositoryOption<T>[];
  selected: readonly T[];
  onChange: (ids: T[]) => void;
  disabled?: boolean;
}) {
  const id = useId();
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const term = query.trim().toLocaleLowerCase();
  const filtered = items.filter((item) => `${item.name} ${item.detail ?? ""}`.toLocaleLowerCase().includes(term));
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const currentPage = Math.min(page, pages - 1);
  const visible = filtered.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);
  const hiddenSelections = selected.filter((value) => !visible.some((item) => item.id === value)).length;

  return <fieldset className="repository-picker" aria-describedby={`${id}-hint`}>
    <legend>{label}</legend>
    <div className="repository-picker-toolbar">
      <label className="repository-picker-search" htmlFor={`${id}-search`}><span>Search repositories</span>
        <input id={`${id}-search`} type="search" value={query} maxLength={200} autoComplete="off"
          placeholder="Filter by repository name" onChange={(event) => { setQuery(event.target.value); setPage(0); }} />
      </label>
      <p className="repository-picker-count" role="status" aria-live="polite" aria-atomic="true">
        <strong>{selected.length} selected</strong><span>{items.length} available{term ? ` · ${filtered.length} matching` : ""}</span>
      </p>
    </div>
    <p id={`${id}-hint`} className="connector-field-hint">Newly available repositories remain unchecked. Search and paging never change your selection.</p>
    {visible.length > 0 ? <ul className="repository-picker-list" tabIndex={0} aria-label="Available repositories">{visible.map((item) => <li key={String(item.id)}>
      <label className="repository-picker-item shared-github-repository-choice" data-selected={selected.includes(item.id)}>
        <input type="checkbox" checked={selected.includes(item.id)} disabled={disabled} onChange={(event) => {
          onChange(event.target.checked ? [...selected, item.id] : selected.filter((value) => value !== item.id));
        }} />
        <span className="connector-choice-copy"><strong>{item.name}</strong>{item.detail && <small>{item.detail}</small>}</span>
      </label>
    </li>)}</ul> : <div className="repository-picker-empty" role="status"><p>No repositories match this search.</p>
      {query && <button type="button" onClick={() => { setQuery(""); setPage(0); }}>Clear search</button>}
    </div>}
    <div className="repository-picker-footer">
      <p className="connector-field-hint">{hiddenSelections > 0 ? `${hiddenSelections} selected ${hiddenSelections === 1 ? "repository is" : "repositories are"} outside this page or search.` : "Only explicitly checked repositories are included."}</p>
      {pages > 1 && <nav aria-label="Repository pages"><button type="button" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous</button>
        <span aria-live="polite">Page {currentPage + 1} of {pages}</span>
        <button type="button" disabled={currentPage === pages - 1} onClick={() => setPage(currentPage + 1)}>Next</button></nav>}
    </div>
  </fieldset>;
}
