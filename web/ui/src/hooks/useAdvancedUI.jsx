import React, { useMemo, useState } from 'react';

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

// Pagination UI Component
export function PaginationControls({ pagination }) {
  const { currentPage, totalPages, goToPage } = pagination;
  
  if (totalPages <= 1) return null;
  
  const pages = [];
  const startPage = Math.max(1, currentPage - 2);
  const endPage = Math.min(totalPages, currentPage + 2);
  
  if (startPage > 1) {
    pages.push(
      <button
        key="first"
        onClick={() => goToPage(1)}
        className="px-3 py-2 border border-gray-300 rounded text-sm font-medium text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:text-gray-300 dark:hover:bg-gray-700"
      >
        1
      </button>
    );
    if (startPage > 2) {
      pages.push(
        <span key="ellipsis1" className="px-3 py-2 text-gray-700 dark:text-gray-300">...</span>
      );
    }
  }
  
  for (let i = startPage; i <= endPage; i++) {
    pages.push(
      <button
        key={i}
        onClick={() => goToPage(i)}
        className={`px-3 py-2 rounded text-sm font-medium transition-colors ${
          i === currentPage
            ? 'bg-blue-600 text-white'
            : 'border border-gray-300 text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:text-gray-300 dark:hover:bg-gray-700'
        }`}
      >
        {i}
      </button>
    );
  }
  
  if (endPage < totalPages) {
    if (endPage < totalPages - 1) {
      pages.push(
        <span key="ellipsis2" className="px-3 py-2 text-gray-700 dark:text-gray-300">...</span>
      );
    }
    pages.push(
      <button
        key="last"
        onClick={() => goToPage(totalPages)}
        className="px-3 py-2 border border-gray-300 rounded text-sm font-medium text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:text-gray-300 dark:hover:bg-gray-700"
      >
        {totalPages}
      </button>
    );
  }
  
  return (
    <div className="flex items-center justify-center gap-2 mt-6">
      <button
        onClick={() => pagination.prevPage()}
        disabled={currentPage === 1}
        className="px-3 py-2 border border-gray-300 rounded text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 dark:border-gray-600 dark:text-gray-300 dark:hover:bg-gray-700"
      >
        Previous
      </button>
      {pages}
      <button
        onClick={() => pagination.nextPage()}
        disabled={currentPage === totalPages}
        className="px-3 py-2 border border-gray-300 rounded text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 dark:border-gray-600 dark:text-gray-300 dark:hover:bg-gray-700"
      >
        Next
      </button>
    </div>
  );
}

// Sort header component for tables
export function SortableHeader({ field, label, sortConfig, onSort, className = '' }) {
  const isActive = sortConfig.field === field;
  const isSortAsc = sortConfig.order === 'asc';
  
  return (
    <th
      onClick={() => onSort(field)}
      className={`px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors ${className}`}
    >
      <div className="flex items-center gap-2">
        {label}
        {isActive && (
          <span className="text-blue-600 dark:text-blue-400">
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
      className={`px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600 dark:text-white dark:placeholder-gray-400 transition-all ${className}`}
    />
  );
}

// Loading skeleton component
export function SkeletonRow({ columns = 5 }) {
  return (
    <tr className="animate-pulse">
      {Array.from({ length: columns }).map((_, i) => (
        <td key={i} className="px-6 py-4 whitespace-nowrap">
          <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-3/4"></div>
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
  const translateX = direction === 'left' ? '-100%' : '100%';
  
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
