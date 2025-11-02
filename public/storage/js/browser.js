const { ScramjetController } = $scramjetLoadController();
const scramjet = new ScramjetController({
  prefix: "/scramjet/",
  files: {
    wasm: "/scram/scramjet.wasm.wasm",
    all: "/scram/scramjet.all.js",
    sync: "/scram/scramjet.sync.js",
  }
});
scramjet.init();
navigator.serviceWorker.register("./sw.js");

const connection = new BareMux.BareMuxConnection("/baremux/worker.js");

const store = {
  url: "https://",
  wispurl:
    _CONFIG?.wispurl ||
    (location.protocol === "https:" ? "wss" : "ws") +
    "://" +
    location.host +
    "/wisp/",
  bareurl:
    _CONFIG?.bareurl ||
    (location.protocol === "https:" ? "https" : "http") +
    "://" +
    location.host +
    "/bare/",
  proxy: "",
  transport: "/epoxy/index.mjs",
  theme: "dark",
  homepage: "petezah://newtab",
  history: JSON.parse(localStorage.getItem("browserHistory") || "[]"),
  zoomLevel: 1,
  favorites: JSON.parse(localStorage.getItem("browserFavorites") || "[]"),
};

async function waitForTransport() {
  let attempts = 0;
  const maxAttempts = 10;

  while (attempts < maxAttempts) {
    try {
      await connection.setTransport("/epoxy/index.mjs", [{ wisp: store.wispurl }]);
      return;
    } catch (e) {
      try {
        await connection.setTransport("/baremux/index.mjs", [store.bareurl]);
        return;
      } catch (e2) {
        try {
          await connection.setTransport("/libcurl/index.mjs", [{ wisp: store.wispurl }]);
          return;
        } catch (e3) {
          attempts++;
          if (attempts >= maxAttempts) {
            console.error("Failed to set any transport after", maxAttempts, "attempts");
            throw new Error("No bare clients available");
          }
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
      }
    }
  }
}

waitForTransport();
let tabs = [];
let activeTabId = 1;
let nextTabId = 2;
let sortableInstance = null;

function getFaviconUrl(url) {
  try {
    const domain = new URL(url).origin;
    return `https://t0.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=${encodeURIComponent(
      domain
    )}`;
  } catch {
    return `https://t0.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=${encodeURIComponent(
      url
    )}`;
  }
}

function createTab(url = store.homepage) {
  const frame = scramjet.createFrame();
  const tab = {
    id: nextTabId++,
    title: "New Tab",
    url: url,
    frame: frame,
    favicon: getFaviconUrl(url),
    zoomLevel: store.zoomLevel,
    muted: false,
    pinned: false,
  };

  frame.frame.src = url === "petezah://newtab" ? "/newpage.html" : url;
  frame.frame.onload = function() {
    try {
      const doc = frame.frame.contentDocument;
      if (doc && (doc.title.includes("Just a moment") || doc.title.includes("Checking your browser"))) {
        frame.frame.src = "/static/google-embed.html#" + encodeURIComponent(tab.url);
      }
    } catch (e) {}
  };

  frame.frame.style.transform = `scale(${tab.zoomLevel})`;
  frame.frame.style.transformOrigin = "0 0";
  frame.frame.style.width = `${100 / tab.zoomLevel}%`;
  frame.frame.style.height = `${100 / tab.zoomLevel}%`;

  frame.addEventListener("urlchange", (e) => {
    if (!e.url) return;
    tab.url = e.url;
    tab.favicon = getFaviconUrl(e.url);

    try {
      const title =
        frame.frame.contentWindow?.document?.title ||
        new URL(e.url).hostname;
      tab.title = title || "...";
    } catch (err) {
      tab.title = new URL(e.url).hostname || "...";
    }

    if (e.url !== "petezah://newtab") {
      store.history.push({ url: e.url, title: tab.title, timestamp: new Date() });
      localStorage.setItem("browserHistory", JSON.stringify(store.history));
    }

    updateTabsUI();
    updateAddressBar();
  });

  tabs.push(tab);
  return tab;
}

function getActiveTab() {
  return tabs.find((tab) => tab.id === activeTabId);
}

function switchTab(tabId) {
  tabs.forEach((tab) => {
    if (tab.frame && tab.frame.frame) {
      tab.frame.frame.classList.add("hidden");
    }
  });

  activeTabId = tabId;
  const activeTab = getActiveTab();
  if (activeTab && activeTab.frame && activeTab.frame.frame) {
    activeTab.frame.frame.classList.remove("hidden");
  }

  updateTabsUI();
  updateAddressBar();
}

function closeTab(tabId) {
  const tabIndex = tabs.findIndex((tab) => tab.id === tabId);
  if (tabIndex === -1) return;

  const tab = tabs[tabIndex];

  if (tab.frame && tab.frame.frame && tab.frame.frame.parentNode) {
    tab.frame.frame.parentNode.removeChild(tab.frame.frame);
  }

  if (tab.frame && typeof tab.frame.destroy === "function") {
    try {
      tab.frame.destroy();
    } catch (e) {
      console.error("Error destroying frame:", e);
    }
  }

  tabs.splice(tabIndex, 1);

  if (tabs.length === 0) {
    const newTab = createTab();
    const iframeContainer = document.getElementById("iframe-container");
    if (iframeContainer) {
      iframeContainer.appendChild(newTab.frame.frame);
    }
    activeTabId = newTab.id;
  } else if (activeTabId === tabId) {
    const newActiveIndex = Math.min(tabIndex, tabs.length - 1);
    activeTabId = tabs[newActiveIndex]?.id;
    if (activeTabId) {
      switchTab(activeTabId);
    }
  }

  updateTabsUI();
}

function muteTab(tabId) {
  const tab = tabs.find((tab) => tab.id === tabId);
  if (tab && tab.frame && tab.frame.frame) {
    tab.muted = !tab.muted;
    tab.frame.frame.muted = tab.muted;
    updateTabsUI();
  }
}

function pinTab(tabId) {
  const tab = tabs.find((tab) => tab.id === tabId);
  if (tab) {
    tab.pinned = !tab.pinned;
    tabs.sort((a, b) => (b.pinned ? 1 : a.pinned ? -1 : 0));
    updateTabsUI();
  }
}

function updateTabsUI() {
  const tabsContainer = document.getElementById("tabs-container");
  if (!tabsContainer) return;

  tabsContainer.innerHTML = "";

  tabs.forEach((tab, index) => {
    if (!tab || !tab.frame) return;
    const tabElement = document.createElement("div");
    tabElement.className = `tab ${tab.id === activeTabId ? "active" : ""} ${tab.pinned ? "pinned" : ""}`;
    tabElement.setAttribute("data-tab-id", tab.id);
    tabElement.onclick = () => switchTab(tab.id);
    tabElement.style.animationDelay = `${index * 0.1}s`;

    const faviconImg = document.createElement("img");
    faviconImg.className = "tab-favicon";
    faviconImg.src = tab.favicon;
    faviconImg.alt = "";
    faviconImg.onerror = () => {
      faviconImg.style.display = "none";
    };

    const titleSpan = document.createElement("span");
    titleSpan.className = "tab-title";
    titleSpan.textContent = tab.title;

    const closeButton = document.createElement("button");
    closeButton.className = "tab-close";
    closeButton.innerHTML = '<i class="fas fa-times"></i>';
    closeButton.onclick = (e) => {
      e.stopPropagation();
      closeTab(tab.id);
    };

    const statusIcons = document.createElement("span");
    statusIcons.className = "tab-status-icons";
    if (tab.muted) {
      const muteIcon = document.createElement("i");
      muteIcon.className = "fas fa-volume-mute";
      statusIcons.appendChild(muteIcon);
    }
    if (tab.pinned) {
      const pinIcon = document.createElement("i");
      pinIcon.className = "fas fa-thumbtack";
      statusIcons.appendChild(pinIcon);
    }

    const infoBox = document.createElement("div");
    infoBox.className = "tab-info-box";
    infoBox.innerHTML = `
      <img src="${tab.favicon}" class="info-favicon" alt="">
      <div>
        <div class="info-title">${tab.title}</div>
        <div class="info-url">${tab.url}</div>
      </div>
    `;

    tabElement.appendChild(faviconImg);
    tabElement.appendChild(titleSpan);
    tabElement.appendChild(statusIcons);
    tabElement.appendChild(closeButton);
    tabElement.appendChild(infoBox);
    tabsContainer.appendChild(tabElement);
  });

  const newTabButton = document.createElement("button");
  newTabButton.className = "new-tab";
  newTabButton.textContent = "+";
  newTabButton.onclick = () => {
    const newTab = createTab();
    const iframeContainer = document.getElementById("iframe-container");
    if (iframeContainer) {
      iframeContainer.appendChild(newTab.frame.frame);
    }
    switchTab(newTab.id);
  };
  tabsContainer.appendChild(newTabButton);

  if (sortableInstance) {
    sortableInstance.destroy();
  }

  sortableInstance = new Sortable(tabsContainer, {
    animation: 300,
    direction: "horizontal",
    ghostClass: "sortable-ghost",
    dragClass: "sortable-drag",
    filter: ".new-tab",
    onStart: () => {
      tabsContainer
        .querySelectorAll(".tab:not(.sortable-ghost)")
        .forEach((t) => {
          t.style.opacity = "0.5";
        });
    },
    onEnd: (evt) => {
      tabsContainer.querySelectorAll(".tab").forEach((t) => {
        t.style.opacity = "1";
      });

      if (evt.oldIndex !== evt.newIndex) {
        const movedTab = tabs.splice(evt.oldIndex, 1)[0];
        tabs.splice(evt.newIndex, 0, movedTab);
      }
    },
  });

  tabsContainer.querySelectorAll(".tab").forEach((tabElement) => {
    tabElement.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      const tabId = parseInt(tabElement.getAttribute("data-tab-id"));
      showTabContextMenu(e, tabId);
    });
  });
}

function showTabContextMenu(event, tabId) {
  const existingMenu = document.getElementById("tab-context-menu");
  if (existingMenu) existingMenu.remove();

  const menu = document.createElement("div");
  menu.id = "tab-context-menu";
  menu.className = "tab-context-menu";
  const tab = tabs.find((t) => t.id === tabId);

  const options = [
    { label: "New Tab", icon: "fa-plus", action: () => {
      const newTab = createTab();
      const iframeContainer = document.getElementById("iframe-container");
      if (iframeContainer) {
        iframeContainer.appendChild(newTab.frame.frame);
      }
      switchTab(newTab.id);
    }},
    { label: "Close Tab", icon: "fa-times", action: () => closeTab(tabId) },
    { label: tab.muted ? "Unmute Tab" : "Mute Tab", icon: tab.muted ? "fa-volume-up" : "fa-volume-mute", action: () => muteTab(tabId) },
    { label: tab.pinned ? "Unpin Tab" : "Pin Tab", icon: "fa-thumbtack", action: () => pinTab(tabId) },
  ];

  options.forEach(({ label, icon, action }) => {
    const item = document.createElement("div");
    item.className = "context-menu-item";
    item.innerHTML = `<i class="fas ${icon}"></i><span>${label}</span>`;
    item.onclick = (e) => {
      e.stopPropagation();
      action();
      menu.remove();
    };
    menu.appendChild(item);
  });

  menu.style.top = `${event.clientY}px`;
  menu.style.left = `${event.clientX}px`;
  document.body.appendChild(menu);

  const closeMenu = (e) => {
    if (!menu.contains(e.target)) {
      menu.remove();
      document.removeEventListener("click", closeMenu);
    }
  };
  document.addEventListener("click", closeMenu);
}

function updateAddressBar() {
  const addressBar = document.getElementById("address-bar");
  const favoriteButton = document.getElementById("favorite-button");
  const activeTab = getActiveTab();
  if (addressBar && activeTab) {
    addressBar.value = activeTab.url;
    const url = activeTab.url;
    if (url.startsWith("petezah://newtab")) {
      activeTab.frame.frame.src = "/newpage.html";
    }
    if (url.startsWith("https://www.youtube.com") || url.startsWith("youtube.com") || url === "www.youtube.com") {
      activeTab.frame.frame.src = "/static/youtube-embed.html#" + url;
    }
    if (url.startsWith("https://discord.com") || url.startsWith("discord.com") || url === "discord.com") {
      activeTab.frame.frame.src = "/static/embed.html#" + url;
    }
    if (url.startsWith("https://www.google.com") || url.startsWith("www.google.com") || url === "www.google.com" || 
        url.startsWith("https://www.google.ca") || url.startsWith("www.google.ca") || url === "www.google.ca") {
      activeTab.frame.frame.src = "/static/google-embed.html";
    }
    const isFavorited = store.favorites.includes(url);
    favoriteButton.innerHTML = `<i class="fas fa-star ${isFavorited ? "favorited" : ""}"></i>`;
  }
}

function toggleFavorite() {
  const activeTab = getActiveTab();
  if (!activeTab) return;
  const url = activeTab.url;
  const index = store.favorites.indexOf(url);
  if (index === -1) {
    store.favorites.push(url);
  } else {
    store.favorites.splice(index, 1);
  }
  localStorage.setItem("browserFavorites", JSON.stringify(store.favorites));
  updateAddressBar();
}

function handleSubmit() {
  const activeTab = getActiveTab();
  const addressBar = document.getElementById("address-bar");
  if (!activeTab || !addressBar) return;

  let url = addressBar.value.trim();

  if (!url.startsWith("http") && !url.includes(".")) {
    url = "https://duckduckgo.com/?q=" + encodeURIComponent(url);
  } else if (!url.startsWith("http") && !url.startsWith("petezah://")) {
    url = "https://" + url;
  }

  if (url.startsWith("https://www.youtube.com") || url === "www.youtube.com") {
    activeTab.frame.frame.src = "/static/youtube-embed.html#https://youtube.com";
    activeTab.url = url;
    activeTab.favicon = getFaviconUrl(url);
    updateTabsUI();
    updateAddressBar();
    return;
  }

  activeTab.url = url;
  activeTab.favicon = getFaviconUrl(url);
  return activeTab.frame.go(url);
}

function showConfig() {
  document.getElementById("config-modal").showModal();
}

function closeConfig() {
  const modal = document.getElementById("config-modal");
  modal.style.opacity = 0;
  setTimeout(() => {
    modal.close();
    modal.style.opacity = 1;
  }, 250);
}

function toggleMenu() {
  const menu = document.getElementById("menu-dropdown");
  menu.classList.toggle("show");
}

function closeAllTabs() {
  tabs.forEach((tab) => {
    if (tab.frame && tab.frame.frame && tab.frame.frame.parentNode) {
      tab.frame.frame.parentNode.removeChild(tab.frame.frame);
    }
    if (tab.frame && typeof tab.frame.destroy === "function") {
      tab.frame.destroy();
    }
  });
  tabs = [];
  const newTab = createTab();
  const iframeContainer = document.getElementById("iframe-container");
  if (iframeContainer) {
    iframeContainer.appendChild(newTab.frame.frame);
  }
  switchTab(newTab.id);
  toggleMenu();
}

function zoomIn() {
  const activeTab = getActiveTab();
  if (activeTab) {
    activeTab.zoomLevel = Math.min(activeTab.zoomLevel + 0.1, 2);
    activeTab.frame.frame.style.transform = `scale(${activeTab.zoomLevel})`;
    activeTab.frame.frame.style.width = `${100 / activeTab.zoomLevel}%`;
    activeTab.frame.frame.style.height = `${100 / activeTab.zoomLevel}%`;
    document.getElementById("zoom-level").textContent = `${Math.round(activeTab.zoomLevel * 100)}%`;
  }
  toggleMenu();
}

function zoomOut() {
  const activeTab = getActiveTab();
  if (activeTab) {
    activeTab.zoomLevel = Math.max(activeTab.zoomLevel - 0.1, 0.5);
    activeTab.frame.frame.style.transform = `scale(${activeTab.zoomLevel})`;
    activeTab.frame.frame.style.width = `${100 / activeTab.zoomLevel}%`;
    activeTab.frame.frame.style.height = `${100 / activeTab.zoomLevel}%`;
    document.getElementById("zoom-level").textContent = `${Math.round(activeTab.zoomLevel * 100)}%`;
  }
  toggleMenu();
}

function toggleFullScreen() {
  const iframeContainer = document.getElementById("iframe-container");
  if (!document.fullscreenElement) {
    iframeContainer.requestFullscreen();
  } else {
    document.exitFullscreen();
  }
  toggleMenu();
}

function showHistory() {
  const modal = document.getElementById("history-modal");
  const historyList = document.getElementById("history-list");
  historyList.innerHTML = store.history
    .slice()
    .reverse()
    .map(
      (item, index) =>
        `<div class="history-item" onclick="createTab('${item.url}'); document.getElementById('iframe-container').appendChild(tabs[tabs.length-1].frame.frame); switchTab(tabs[tabs.length-1].id); document.getElementById('history-modal').close();">
          <span>${item.title}</span><br>
          <small>${item.url} - ${new Date(item.timestamp).toLocaleString()}</small>
        </div>`
    )
    .join("");
  modal.showModal();
  toggleMenu();
}

function fixProxy() {
  navigator.serviceWorker.getRegistrations().then(registrations => {
    const unregisterPromises = registrations.map(reg =>
      reg.unregister().then(success => {
        console.log(`Service Worker unregistered: ${success}`);
      })
    );

    Promise.all(unregisterPromises).then(() => {
      const dbName = '$scramjet';
      const request = indexedDB.deleteDatabase(dbName);

      request.onsuccess = () => {
        console.log(`Deleted IndexedDB: ${dbName}`);
      };
      request.onerror = () => {
        console.error(`Failed to delete IndexedDB: ${dbName}`);
      };
      request.onblocked = () => {
        console.warn(`Delete blocked for IndexedDB: ${dbName}`);
      };

      localStorage.setItem('bare-mux-path', '/baremux/worker.js');
    });
  });
}

function showSecurePopup() {
  const existingPopup = document.getElementById("secure-popup");
  if (existingPopup) existingPopup.remove();

  const popup = document.createElement("div");
  popup.id = "secure-popup";
  popup.className = "secure-popup";
  popup.innerHTML = `
    <div class="secure-message">Website is secure and proxy forwarding is active over WISP</div>
    <div class="secure-icon"><i class="fas fa-circle active"></i></div>
  `;
  document.body.appendChild(popup);

  const addressBar = document.getElementById("address-bar");
  const rect = addressBar.getBoundingClientRect();
  popup.style.top = `${rect.bottom + 5}px`;
  popup.style.left = `${rect.left}px`;

  const closePopup = (e) => {
    if (!popup.contains(e.target)) {
      popup.remove();
      document.removeEventListener("click", closePopup);
    }
  };
  document.addEventListener("click", closePopup);
}

class Search {
  constructor(scramjet, store) {
    this.scramjet = scramjet;
    this.store = store;
    this.currentSectionIndex = 0;
    this.maxResults = 8;
    this.sections = {};
    this.selectedSuggestionIndex = -1;
  }

  init() {
    const addressBar = document.getElementById("address-bar");
    const nav = document.querySelector(".nav");
    const suggestionList = document.createElement("div");
    suggestionList.id = "suggestion-list";
    suggestionList.className = "suggestion-list";
    nav.appendChild(suggestionList);

    this.sections = {
      searchResults: this.createSection("Search Results"),
      history: this.createSection("History"),
    };

    Object.values(this.sections).forEach(({ section }) => suggestionList.appendChild(section));

    addressBar.addEventListener("input", async (event) => {
      suggestionList.style.display = "flex";
      const query = event.target.value.trim();
      if (query === "" && event.inputType === "deleteContentBackward") {
        this.clearSuggestions();
        suggestionList.style.display = "none";
        return;
      }

      let cleanedQuery = query.replace(/^(petezah:\/\/|petezah:\/|petezah:)/, "");
      const suggestions = await this.generateSuggestions(cleanedQuery);
      this.clearSuggestions();
      this.populateSections(suggestions, query);
    });

    addressBar.addEventListener("keydown", (event) => {
      if (event.key === "Escape" || event.ctrlKey || event.shiftKey || event.altKey || event.metaKey) {
        suggestionList.style.display = "none";
        this.clearSuggestions();
        return;
      }

      const suggestionItems = this.getCurrentSuggestionItems();
      const numSuggestions = suggestionItems.length;

      if (event.key === "ArrowDown") {
        event.preventDefault();
        if (this.selectedSuggestionIndex + 1 >= numSuggestions) {
          this.moveToNextSection();
          this.selectedSuggestionIndex = 0;
        } else {
          this.selectedSuggestionIndex = (this.selectedSuggestionIndex + 1) % numSuggestions;
        }
        this.updateSelectedSuggestion();
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        if (this.selectedSuggestionIndex <= 0) {
          this.moveToPreviousSection();
        } else {
          this.selectedSuggestionIndex = (this.selectedSuggestionIndex - 1 + numSuggestions) % numSuggestions;
        }
        this.updateSelectedSuggestion();
      } else if (event.key === "Tab" || event.key === "ArrowRight") {
        if (this.selectedSuggestionIndex !== -1) {
          event.preventDefault();
          const selectedSuggestion = suggestionItems[this.selectedSuggestionIndex].querySelector(".suggestion-text").textContent;
          addressBar.value = selectedSuggestion;
          this.clearSuggestions();
          suggestionList.style.display = "none";
        }
      } else if (event.key === "Enter") {
        event.preventDefault();
        if (this.selectedSuggestionIndex !== -1) {
          const selectedSuggestion = suggestionItems[this.selectedSuggestionIndex].querySelector(".suggestion-text").textContent;
          addressBar.value = selectedSuggestion;
          this.clearSuggestions();
          suggestionList.style.display = "none";
          handleSubmit();
        } else {
          this.clearSuggestions();
          suggestionList.style.display = "none";
          handleSubmit();
        }
      } else if (event.key === "Backspace" && addressBar.value === "") {
        suggestionList.style.display = "none";
        this.clearSuggestions();
      }
    });

    document.addEventListener("click", (e) => {
      if (!addressBar.contains(e.target) && !suggestionList.contains(e.target)) {
        suggestionList.style.display = "none";
        this.clearSuggestions();
      }
    });
  }

  createSection(titleText) {
    const section = document.createElement("div");
    section.className = "search-section";
    const searchTitle = document.createElement("div");
    searchTitle.className = "search-title";
    const icon = document.createElement("img");
    icon.src = "/storage/images/logo-png-removebg-preview.png";
    icon.className = "searchEngineIcon";
    const title = document.createElement("span");
    title.textContent = titleText;
    searchTitle.appendChild(icon);
    searchTitle.appendChild(title);
    const searchResults = document.createElement("div");
    searchResults.className = "search-results";
    section.appendChild(searchTitle);
    section.appendChild(searchResults);
    return { section, searchResults };
  }

  async generateSuggestions(query) {
    try {
      const response = await fetch(`/results/${encodeURIComponent(query)}`);
      if (!response.ok) throw new Error("Network response was not ok");
      const data = await response.json();
      return data.map((item) => item.phrase);
    } catch (error) {
      console.error("Error fetching suggestions:", error);
      return [];
    }
  }

  populateSections(suggestions, query) {
    this.populateSearchResults(suggestions);
    this.populateHistory(query);
  }

  populateSearchResults(suggestions) {
    const { searchResults, section } = this.sections.searchResults;
    if (suggestions.length > 0) {
      section.style.display = "block";
      suggestions.slice(0, this.maxResults).forEach((suggestion) => {
        const listItem = this.createSuggestionItem(suggestion);
        searchResults.appendChild(listItem);
      });
    } else {
      section.style.display = "none";
    }
  }

  populateHistory(query) {
    const { searchResults, section } = this.sections.history;
    const lowerQuery = query.toLowerCase();
    const filteredHistory = this.store.history
      .filter((item) => item.url.toLowerCase().includes(lowerQuery) || item.title.toLowerCase().includes(lowerQuery))
      .slice(0, this.maxResults);

    if (filteredHistory.length > 0) {
      section.style.display = "block";
      filteredHistory.forEach((item) => {
        const listItem = this.createSuggestionItem(item.url, item.title);
        searchResults.appendChild(listItem);
      });
    } else {
      section.style.display = "none";
    }
  }

  createSuggestionItem(url, title = url) {
    const listItem = document.createElement("div");
    const listIcon = document.createElement("i");
    listIcon.className = "fas fa-search";
    const listSuggestion = document.createElement("span");
    listSuggestion.className = "suggestion-text";
    listSuggestion.textContent = title;
    listItem.appendChild(listIcon);
    listItem.appendChild(listSuggestion);
    listItem.addEventListener("click", () => {
      const addressBar = document.getElementById("address-bar");
      addressBar.value = url;
      this.clearSuggestions();
      document.getElementById("suggestion-list").style.display = "none";
      handleSubmit();
    });
    return listItem;
  }

  clearSuggestions() {
    Object.values(this.sections).forEach(({ searchResults, section }) => {
      searchResults.innerHTML = "";
      section.style.display = "none";
    });
    this.selectedSuggestionIndex = -1;
    this.currentSectionIndex = 0;
  }

  getCurrentSuggestionItems() {
    return Object.values(this.sections)[this.currentSectionIndex].searchResults.querySelectorAll("div");
  }

  moveToNextSection() {
    const sectionsArray = Object.values(this.sections);
    this.currentSectionIndex = (this.currentSectionIndex + 1) % sectionsArray.length;
    while (sectionsArray[this.currentSectionIndex].searchResults.children.length === 0) {
      this.currentSectionIndex = (this.currentSectionIndex + 1) % sectionsArray.length;
    }
    this.selectedSuggestionIndex = -1;
    this.updateSelectedSuggestion();
  }

  moveToPreviousSection() {
    const sectionsArray = Object.values(this.sections);
    this.currentSectionIndex = (this.currentSectionIndex - 1 + sectionsArray.length) % sectionsArray.length;
    while (sectionsArray[this.currentSectionIndex].searchResults.children.length === 0) {
      this.currentSectionIndex = (this.currentSectionIndex - 1 + sectionsArray.length) % sectionsArray.length;
    }
    const previousSectionItems = this.getCurrentSuggestionItems();
    this.selectedSuggestionIndex = previousSectionItems.length - 1;
    this.updateSelectedSuggestion();
  }

  updateSelectedSuggestion() {
    const suggestionItems = this.getCurrentSuggestionItems();
    document.querySelectorAll(".search-results div.selected").forEach((item) => {
      item.classList.remove("selected");
    });
    suggestionItems.forEach((item, index) => {
      item.classList.toggle("selected", index === this.selectedSuggestionIndex);
    });
  }
}

window.addEventListener("load", async () => {
  const root = document.getElementById("app");

  root.innerHTML = `
    <div class="browser-container">
      <dialog id="config-modal" class="cfg">
        <h2>Settings</h2>
        <div class="flex col input_row">
          <label for="wisp_url_input">Wisp:</label>
          <input id="wisp_url_input" value="${store.wispurl}" spellcheck="false">
        </div>
        <div class="flex col input_row">
          <label for="bare_url_input">Bare:</label>
          <input id="bare_url_input" value="${store.bareurl}" spellcheck="false">
        </div>
        <div class="flex col input_row">
          <label for="homepage_input">Homepage:</label>
          <input id="homepage_input" value="${store.homepage}" spellcheck="false">
        </div>
        <div class="flex buttons">
          <button onclick="fixProxy();">Fix Proxy</button>
        </div>
        <div class="flex buttons centered">
          <button onclick="closeConfig()">x</button>
        </div>
      </dialog>

      <dialog id="history-modal" class="history-modal">
        <h2>Browsing History</h2>
        <div id="history-list" style="max-height: 300px; overflow-y: auto;"></div>
        <div class="flex buttons centered">
          <button onclick="document.getElementById('history-modal').close()">x</button>
        </div>
      </dialog>

      <div class="flex tabs" id="tabs-container"></div>

      <div class="flex nav">
        <button onclick="showConfig()" title="Settings"><i class="fas fa-cog"></i></button>
        <button onclick="getActiveTab()?.frame.back()" title="Back"><i class="fas fa-chevron-left"></i></button>
        <button onclick="getActiveTab()?.frame.forward()" title="Forward"><i class="fas fa-chevron-right"></i></button>
        <button onclick="getActiveTab()?.frame.reload()" title="Reload"><i class="fas fa-rotate-right"></i></button>
        <div class="address-bar-container">
          <button id="secure-icon" onclick="showSecurePopup()" title="Site Info"><i class="fas fa-lock"></i></button>
          <input class="bar" id="address-bar" autocomplete="off" autocapitalize="off" autocorrect="off"
            onkeyup="event.keyCode === 13 && handleSubmit()" placeholder="Enter URL or search query">
          <button id="favorite-button" onclick="toggleFavorite()" title="Favorite"><i class="fas fa-star"></i></button>
        </div>
        <button onclick="window.open(scramjet.encodeUrl(getActiveTab()?.url))" title="Open in new window"><i class="fas fa-arrow-up-right-from-square"></i></button>
        <button class="menu-btn" onclick="toggleMenu()" title="Menu"><i class="fas fa-ellipsis-v"></i></button>
        <div class="menu-dropdown" id="menu-dropdown">
          <button onclick="createTab(); document.getElementById('iframe-container').appendChild(tabs[tabs.length-1].frame.frame); switchTab(tabs[tabs.length-1].id); toggleMenu()">
            <i class="fas fa-plus"></i>
            <span>New Tab</span>
          </button>
          <button onclick="closeAllTabs()">
            <i class="fas fa-times"></i>
            <span>Close All Tabs</span>
          </button>
          <div class="zoom-controls">
            <button onclick="zoomOut()"><i class="fas fa-minus"></i></button>
            <span id="zoom-level">100%</span>
            <button onclick="zoomIn()"><i class="fas fa-plus"></i></button>
          </div>
          <button onclick="showHistory()">
            <i class="fas fa-history"></i>
            <span>History</span>
          </button>
          <button onclick="toggleFullScreen()">
            <i class="fas fa-expand"></i>
            <span>Fullscreen</span>
          </button>
        </div>
      </div>

      <div class="iframe-container" id="iframe-container"></div>
    </div>
  `;

  const initialTab = createTab();
  const iframeContainer = document.getElementById("iframe-container");
  if (iframeContainer) {
    iframeContainer.appendChild(initialTab.frame.frame);
  }
  switchTab(initialTab.id);
  updateTabsUI();

  const search = new Search(scramjet, store);
  search.init();

  document.getElementById("wisp_url_input").addEventListener("change", (e) => {
    store.wispurl = e.target.value;
  });
  document.getElementById("bare_url_input").addEventListener("change", (e) => {
    store.bareurl = e.target.value;
  });
  document.getElementById("homepage_input").addEventListener("change", (e) => {
    store.homepage = e.target.value;
  });

  document.addEventListener("click", (e) => {
    const menu = document.getElementById("menu-dropdown");
    const menuBtn = document.querySelector(".menu-btn");
    if (!menu.contains(e.target) && !menuBtn.contains(e.target)) {
      menu.classList.remove("show");
    }
  });

  try {
    function b64(buffer) {
      let binary = "";
      const bytes = new Uint8Array(buffer);
      const len = bytes.byteLength;
      for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary);
    }
    console.log(
      "%cb",
      `
        background-image: url(data:image/png;base64,${b64(arraybuffer)});
        color: transparent;
        padding-left: 200px;
        padding-bottom: 100px;
        background-size: contain;
        background-position: center center;
        background-repeat: no-repeat;
      `
    );
  } catch (e) {}
});
