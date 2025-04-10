
  function showLoginPrompt() {
    toggleChat();
  }

  async function sendQuestion() {
    const input = document.getElementById("userInput");
    const question = input.value.trim();
    const chatBody = document.getElementById("chatBody");

    if (!question) return;

    // Add user message
    chatBody.innerHTML += `<div class="user-message">${escapeHtml(
      question
    )}</div>`;

    // Add loading indicator with unique ID
    const loadingId = `loading-${Date.now()}`;
    chatBody.innerHTML += `
        <div id="${loadingId}" class="assistant-message loading-indicator">
            <i class="fas fa-spinner fa-spin"></i> Finding products...
        </div>
    `;

    // Clear input field
    input.value = "";
    chatBody.scrollTop = chatBody.scrollHeight;

    try {
      const response = await fetch("/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question }),
      });

      // Remove loading indicator
      const loadingMessage = document.getElementById(loadingId);
      if (loadingMessage) {
        loadingMessage.remove();
      }

      // Get response data
      const data = await response.json();

      if (response.ok && data.answer) {
        // Ensure we have an actual answer with content
        if (data.answer.trim() === "") {
          chatBody.innerHTML += `
                    <div class="assistant-message">
                        I'm sorry, I couldn't find that information. Can I help you with something else?
                    </div>`;
        } else {
          // Clean up any potential markdown formatting
          let cleanAnswer = data.answer
            .replace(/\\boxed\{/g, "")
            .replace(/\}/g, "")
            .replace(/```/g, "")
            .trim();

          chatBody.innerHTML += `<div class="assistant-message">${cleanAnswer}</div>`;
        }
      } else {
        // Display error message from server
        const errorMessage =
          data.error || "Something went wrong. Please try again.";
        chatBody.innerHTML += `
                <div class="assistant-message error">
                    ${errorMessage}
                </div>`;
      }
    } catch (error) {
      // Handle network errors
      const loadingMessage = document.getElementById(loadingId);
      if (loadingMessage) {
        loadingMessage.remove();
      }

      console.error("Chat error:", error);

      chatBody.innerHTML += `
            <div class="assistant-message error">
                Connection issue - please check your network and try again.
            </div>`;
    }

    chatBody.scrollTop = chatBody.scrollHeight;
  }

  // Function to escape HTML to prevent XSS
  function escapeHtml(unsafe) {
    return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Handle Enter key in the input field
  document
    .getElementById("userInput")
    .addEventListener("keypress", function (event) {
      if (event.key === "Enter") {
        event.preventDefault();
        sendQuestion();
      }
    });

  function toggleChat() {
    const chatPopup = document.getElementById("chatPopup");
    chatPopup.style.display =
      chatPopup.style.display === "none" || chatPopup.style.display === ""
        ? "block"
        : "none";

    // Focus the input field when opening chat
    if (chatPopup.style.display === "block") {
      document.getElementById("userInput").focus();
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    const searchBar = document.getElementById("search-bar");
    const filterCategory = document.getElementById("filter-category");
    const filterTag = document.getElementById("filter-tag");

    // Attach event listeners
    searchBar.addEventListener("input", searchItems);
    filterCategory.addEventListener("change", filterItems);
    filterTag.addEventListener("change", filterItems);

    function filterItems() {
      const categoryId = filterCategory.value;
      const tagId = filterTag.value;

      fetch("/filter", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          category_id: categoryId,
          tag_id: tagId,
        }),
      })
        .then((response) => response.json())
        .then((filteredItems) => {
          const wrapper = document.querySelector(".wrapper");
          wrapper.innerHTML = "";

          if (filteredItems.length === 0) {
            wrapper.innerHTML =
              '<div class="alert alert-info w-100 text-center">No items found matching your criteria.</div>';
            return;
          }

          filteredItems.forEach((item) => {
            const card = document.createElement("div");
            card.classList.add("product-list");

            const imageUrl = item.image_url
              ? `/static/${item.image_url}`
              : "/static/images/no_image.png";

            card.innerHTML = `
          <div class="card position-relative shadow-sm border-0 rounded-4 overflow-hidden">
            <div class="position-absolute top-0 start-0 m-3 d-flex align-items-center gap-1">
              <!-- Optional love icon or badge -->
            </div>

            <img src="${imageUrl}" class="item-image" alt="${item.name}" />

            <div class="card-body text-center">
              <a class="card-title fw-semibold mb-1" href="/product/${item.id}">
                ${item.name}
              </a>
              <p class="card-text mb-1">
                <span class="fw-bold fs-4 price">$${item.price}</span>
              </p>
              <p class="card-text text-muted small">
                ${
                  item.description
                    ? item.description.substring(0, 100) + "..."
                    : "No description available"
                }
              </p>
              <button class="btn rounded-pill px-4 mt-2 add-to-cart" data-item-id="${
                item.id
              }">
                add to cart
              </button>
              <button class="btn btn-dark rounded-pill px-4 mt-2 w-100 add-to-wishlist" data-item-id="${
                item.id
              }">
                add to wishlist
              </button>
            </div>
          </div>
        `;

            wrapper.appendChild(card);
          });

          setupAddToCartButtons();
          setupAddToWishlistButtons();
          searchItems(); // Keep this if you're enabling live filtering/search
        })
        .catch((error) => {
          console.error("Error filtering items:", error);
          const wrapper = document.querySelector(".wrapper");
          wrapper.innerHTML =
            '<div class="alert alert-danger w-100 text-center">Error loading items. Please try again.</div>';
        });
    }

    function searchItems() {
      const query = searchBar.value.toLowerCase();

      // Select all cards and filter based on the query
      document.querySelectorAll(".product-list").forEach((card) => {
        const title = card
          .querySelector(".card-title")
          .textContent.toLowerCase();
        const matchesQuery = query === "" || title.includes(query);

        // Show or hide cards based on the search query
        card.style.display = matchesQuery ? "" : "none";
      });
    }

    function setupAddToWishlistButtons() {
      document.querySelectorAll(".add-to-wishlist").forEach((button) => {
        button.addEventListener("click", function (e) {
          e.preventDefault();
          const itemId = this.dataset.itemId;
          const originalText = this.innerHTML;

          this.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Adding...';
          this.disabled = true;

          fetch(`/wishlist/add/${itemId}`, { method: "POST" })
            .then((response) => response.json())
            .then((data) => {
              if (data.success) {
                this.innerHTML = '<i class="fa fa-check"></i> Added!';
                updateCounters();
                showNotification("Item added to wishlist!", "success");
              } else {
                throw new Error(data.error || "Failed to add to wishlist");
              }
            })
            .catch((error) => {
              console.error("Error:", error);
              this.innerHTML = '<i class="fa fa-times"></i> Failed';
              showNotification("Error adding to wishlist", "danger");
            })
            .finally(() => {
              setTimeout(() => {
                this.innerHTML = originalText;
                this.disabled = false;
              }, 1500);
            });
        });
      });
    }

    // Initialize wishlist buttons
    setupAddToWishlistButtons();
  });

