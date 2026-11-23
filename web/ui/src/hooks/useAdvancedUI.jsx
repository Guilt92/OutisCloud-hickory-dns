import React, { useEffect, useMemo, useRef, useState, useCallback } from 'react';

// Pagination hook for large datasets
export function usePagination(items, itemsPerPage = 10) {
  const [currentPage, setCurrentPage] = useState(1);
  
  const paginationData = useMemo(() => {
    const totalPages = Math.ceil(items.length / itemsPerPage);
    const startIdx = (currentPage - 1) * itemsPerPage;
    const endIdx = startIdx + itemsPerPage;
    const currentItems = items.slice(startIdx, endIdx);
    
    return {
      currentItems,
      currentPage,
      totalPages,
      totalItems: items.length,
      itemsPerPage,
      setCurrentPage,
      goToPage: (page) => setCurrentPage(Math.min(Math.max(1, page), totalPages)),
      nextPage: () => setCurrentPage(prev => Math.min(prev + 1, totalPages)),
      prevPage: () => setCurrentPage(prev => Math.max(prev - 1, 1)),
    };
  }, [items, currentPage, itemsPerPage]);
  
  return paginationData;
}

// Server-side pagination + search. Calls `<path>?limit&offset&q` and reads the
// total from the X-Total-Count header; `normalize` maps the response body to a
// list. Returns an object compatible with <PaginationControls/>.
export function useServerPagination(api, path, { pageSize = 20, normalize = (d) => d || [], extraParams = {} } = {}) {
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState('');
  const [debounced, setDebounced] = useState('');
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [tick, setTick] = useState(0);
  const seq = useRef(0);

  useEffect(() => {
    const t = setTimeout(() => { setDebounced(query.trim()); setPage(1); }, 300);
    return () => clearTimeout(t);
  }, [query]);

  useEffect(() => {
    if (!path) return;
    const my = ++seq.current;
    setLoading(true);
    const params = { limit: pageSize, offset: (page - 1) * pageSize, ...extraParams };
    if (debounced) params.q = debounced;
    api.get(path, { params })
      .then((r) => {
        if (my !== seq.current) return; // a newer request superseded this one
        const list = normalize(r.data);
        const count = Number(r.headers?.['x-total-count']);
        const totalCount = Number.isFinite(count) ? count : list.length;
        const pages = Math.max(1, Math.ceil(totalCount / pageSize));
        if (page > pages) { setPage(pages); return; } // e.g. last item on the page was deleted
        setItems(list); setTotal(totalCount); setError(null);
      })
      .catch((e) => { if (my === seq.current) setError(e); })
      .finally(() => { if (my === seq.current) setLoading(false); });
  }, [api, path, page, pageSize, debounced, tick, JSON.stringify(extraParams)]); // eslint-disable-line react-hooks/exhaustive-deps

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const reload = useCallback(() => setTick((t) => t + 1), []);
  const pagination = {
    currentItems: items, currentPage: page, totalPages, totalItems: total, itemsPerPage: pageSize,
    setCurrentPage: setPage,
    goToPage: (n) => setPage(Math.min(Math.max(1, n), totalPages)),
    nextPage: () => setPage((p) => Math.min(p + 1, totalPages)),
    prevPage: () => setPage((p) => Math.max(p - 1, 1)),
  };
  return { items, total, loading, error, query, setQuery, reload, pagination };
}

// Table sorting hook
export function useTableSort(items, defaultSort = { field: 'id', order: 'asc' }) {
  const [sortConfig, setSortConfig] = useState(defaultSort);
  
  const sortedItems = useMemo(() => {
    const sorted = [...items].sort((a, b) => {
      const aVal = a[sortConfig.field];
      const bVal = b[sortConfig.field];
      
      if (aVal === null) return 1;
      if (bVal === null) return -1;
      if (aVal === bVal) return 0;
      
      const comparison = aVal < bVal ? -1 : 1;
      return sortConfig.order === 'asc' ? comparison : -comparison;
    });
    
    return sorted;
  }, [items, sortConfig]);
  
  const requestSort = (field) => {
    let order = 'asc';
    if (sortConfig.field === field && sortConfig.order === 'asc') {
      order = 'desc';
    }
    setSortConfig({ field, order });
  };
  
  return {
    sortedItems,
    sortConfig,
    requestSort,
  };
}

// Advanced search with debouncing
export function useAdvancedSearch(items, searchableFields = []) {
  const [searchTerm, setSearchTerm] = useState('');
  const [searchTimeout, setSearchTimeout] = useState(null);
  
  const filteredItems = useMemo(() => {
    if (!searchTerm.trim()) return items;
    
    const term = searchTerm.toLowerCase();
    return items.filter(item => 
      searchableFields.some(field => {
        const value = item[field];
        return value && value.toString().toLowerCase().includes(term);
      })
    );
  }, [items, searchTerm, searchableFields]);
  
  const handleSearch = (term) => {
    if (searchTimeout) clearTimeout(searchTimeout);
    
    const timeout = setTimeout(() => {
      setSearchTerm(term);
    }, 300);
    
    setSearchTimeout(timeout);
  };
  
  return {
    searchTerm,
    filteredItems,
    handleSearch,
    clearSearch: () => setSearchTerm(''),
  };
}

// Pagination UI component (design-system styled)
export function PaginationControls({ pagination }) {
  const { currentPage, totalPages, goToPage } = pagination;
  if (totalPages <= 1) return null;

  const pages = [];
  for (let i = Math.max(1, currentPage - 1); i <= Math.min(totalPages, currentPage + 1); i++) pages.push(i);
  if (pages[0] > 1) { if (pages[0] > 2) pages.unshift('…'); pages.unshift(1); }
  if (pages[pages.length - 1] < totalPages) { if (pages[pages.length - 1] < totalPages - 1) pages.push('…'); pages.push(totalPages); }

  const base = 'min-w-[2rem] h-8 px-2 rounded-md text-sm font-medium transition-colors';
  return (
    <nav className="flex items-center gap-1" aria-label="Pagination">
      <button type="button" onClick={() => goToPage(currentPage - 1)} disabled={currentPage === 1}
        className={`${base} text-muted hover:text-ink hover:bg-ink/5 disabled:opacity-40 disabled:hover:bg-transparent`}>Prev</button>
      {pages.map((p, i) => p === '…'
        ? <span key={`e${i}`} className="px-1 text-muted" aria-hidden="true">…</span>
        : <button type="button" key={p} onClick={() => goToPage(p)} aria-current={p === currentPage ? 'page' : undefined}
            className={`${base} ${p === currentPage ? 'bg-accent text-on-accent' : 'text-muted hover:text-ink hover:bg-ink/5'}`}>{p}</button>)}
      <button type="button" onClick={() => goToPage(currentPage + 1)} disabled={currentPage === totalPages}
        className={`${base} text-muted hover:text-ink hover:bg-ink/5 disabled:opacity-40 disabled:hover:bg-transparent`}>Next</button>
    </nav>
  );
}

// Sort header component for tables
export function SortableHeader({ field, label, sortConfig, onSort, className = '' }) {
  const isActive = sortConfig.field === field;
  const isSortAsc = sortConfig.order === 'asc';
  
  return (
    <th
      onClick={() => onSort(field)}
      className={`px-4 py-3 text-left text-[11px] font-semibold text-muted uppercase tracking-[0.12em] cursor-pointer hover:text-ink hover:bg-surface-2 transition-colors ${className}`}
    >
      <div className="flex items-center gap-2">
        {label}
        {isActive && (
          <span className="text-ink" aria-hidden="true">
            {isSortAsc ? '↑' : '↓'}
          </span>
        )}
      </div>
    </th>
  );
}

// Debounced search input
export function DebouncedSearchInput({ value, onChange, placeholder, className = '' }) {
  return (
    <input
      type="text"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      aria-label={placeholder || 'Search'}
      className={`input ${className}`}
    />
  );
}

// Loading skeleton component
export function SkeletonRow({ columns = 5 }) {
  return (
    <tr className="animate-pulse">
      {Array.from({ length: columns }).map((_, i) => (
        <td key={i} className="px-6 py-4 whitespace-nowrap">
          <div className="skeleton h-4 rounded w-3/4"></div>
        </td>
      ))}
    </tr>
  );
}

export function SkeletonTable({ rows = 5, columns = 5 }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, i) => (
        <SkeletonRow key={i} columns={columns} />
      ))}
    </>
  );
}

// Fade animation wrapper
export function FadeIn({ children, duration = 300, className = '' }) {
  return (
    <div
      className={className}
      style={{
        animation: `fadeIn ${duration}ms ease-in`,
      }}
    >
      {children}
      <style>{`
        @keyframes fadeIn {
          from {
            opacity: 0;
            transform: translateY(-10px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
      `}</style>
    </div>
  );
}

// Slide animation wrapper
export function SlideIn({ children, direction = 'left', duration = 300, className = '' }) {
  return (
    <div
      className={className}
      style={{
        animation: `slideIn${direction === 'left' ? 'Left' : 'Right'} ${duration}ms ease-out`,
      }}
    >
      {children}
      <style>{`
        @keyframes slideInLeft {
          from {
            opacity: 0;
            transform: translateX(-100%);
          }
          to {
            opacity: 1;
            transform: translateX(0);
          }
        }
        @keyframes slideInRight {
          from {
            opacity: 0;
            transform: translateX(100%);
          }
          to {
            opacity: 1;
            transform: translateX(0);
          }
        }
      `}</style>
    </div>
  );
}

// Bounce animation for notifications
export function BounceIn({ children, duration = 400, className = '' }) {
  return (
    <div
      className={className}
      style={{
        animation: `bounceIn ${duration}ms cubic-bezier(0.68, -0.55, 0.265, 1.55)`,
      }}
    >
      {children}
      <style>{`
        @keyframes bounceIn {
          from {
            opacity: 0;
            transform: scale(0.3);
          }
          50% {
            opacity: 1;
            transform: scale(1.05);
          }
          70% {
            transform: scale(0.9);
          }
          to {
            transform: scale(1);
          }
        }
      `}</style>
    </div>
  );
}
