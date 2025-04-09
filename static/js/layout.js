// Showing and hiding the cart
document.addEventListener("DOMContentLoaded", function() {
  const cartIcon = document.querySelector("#cart-icon");
  const cart = document.querySelector(".cart");
  const cartClose = document.querySelector("#cart-close");

  // Open cart
  if (cartIcon) {
    cartIcon.addEventListener("click", () => {
      cart.classList.add("active");
    });
  }

  // Close cart
  if (cartClose) {
    cartClose.addEventListener("click", () => {
      cart.classList.remove("active");
    });
  }

  // Add event listeners for update-quantity buttons
  document.querySelectorAll(".update-quantity").forEach((button) => {
    button.addEventListener("click", function () {
      const cartItemId = this.dataset.cartItemId;
      const action = this.dataset.action;

      fetch(`/cart/update/${cartItemId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      })
        .then((response) => response.json())
        .then((data) => {
          // Ensure data contains the expected properties
          if (!data.quantity || !data.total_price || !data.cart_total) {
            throw new Error("Invalid response data");
          }

          // Parse `total_price` and `cart_total` to ensure they are numbers
          const totalPrice = parseFloat(data.total_price);
          const cartTotal = parseFloat(data.cart_total);

          if (isNaN(totalPrice) || isNaN(cartTotal)) {
            throw new Error("Total price or cart total is not a valid number");
          }

          // Update quantity and total price for the specific cart item
          const cartBox = this.closest(".cart-box");
          cartBox.querySelector(".quantity").textContent = data.quantity;
          cartBox.querySelector(".carttotal" + cartItemId).textContent = `$${totalPrice.toFixed(2)}`;
          
          // Update overall cart total
          updateCartTotal(cartTotal);
          
          // Update badge count
          document.getElementById("cart-badge").textContent = getCartItemCount();
        })
        .catch((error) => {
          console.log("Error updating quantity:", error);
        });
    });
  });

  // Attach event listeners to remove buttons
  document.querySelectorAll(".remove-from-cart").forEach((button) => {
    button.addEventListener("click", function () {
      const cartItemId = this.dataset.cartItemId;
      removeCartItem(cartItemId); // Remove the item from the cart
    });
  });
  
  // Setup add to cart buttons on product cards
  setupAddToCartButtons();

  // Setup add to wishlist buttons
  setupAddToWishlistButtons();
  
  // Setup mobile touch support
  setupMobileTouchSupport();
});

// Get total count of items in cart
function getCartItemCount() {
  let count = 0;
  document.querySelectorAll('.cart-box .quantity').forEach(quantityEl => {
    count += parseInt(quantityEl.textContent);
  });
  return count;
}

// Function to remove item from cart using AJAX
function removeCartItem(cartItemId) {
  fetch(`/cart/remove/${cartItemId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" }
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      // Remove the specific cart item from the DOM
      const cartItemElement = document.querySelector(`[data-cart-item-id="${cartItemId}"]`).closest(".cart-box");
      if (cartItemElement) {
        cartItemElement.remove();
      }
      
      updateCartTotal(data.cart_total);
      
      // Update badge count
      document.getElementById("cart-badge").textContent = data.cart_count;
    
      if (data.cart_items.length === 0) {
        document.querySelector(".cart-content").innerHTML = "<p>Your cart is empty.</p>";
      }
    } else {
      console.error("Error removing item:", data.error);
    }
  })
  .catch(error => console.error("Error removing item:", error));
}

// Function to update total price
function updateCartTotal(newTotal) {
  // Ensure newTotal is a number and format it properly
  const total = parseFloat(newTotal);
  const totalPriceElement = document.querySelector(".total-price");
  
  if (totalPriceElement) {
    if (isNaN(total)) {
      totalPriceElement.textContent = "$0.00";
    } else {
      totalPriceElement.textContent = `$${total.toFixed(2)}`;
    }
  }
}

// Set up add to cart buttons on product cards
function setupAddToCartButtons() {
  document.querySelectorAll(".add-to-cart").forEach((button) => {
    // Store original text for later
    if (!button.getAttribute('data-original-text')) {
      button.setAttribute('data-original-text', button.innerHTML);
    }
    
    button.addEventListener("click", function (e) {
      e.preventDefault();
      
      // Skip if button is already processing
      if (this.disabled) return;
      
      const itemId = this.dataset.itemId;
      addItemToCart(itemId, this);
    });
  });
}

// Set up add to wishlist buttons
function setupAddToWishlistButtons() {
  document.querySelectorAll(".add-to-wishlist").forEach((button) => {
    // Store original text for later
    if (!button.getAttribute('data-original-text')) {
      button.setAttribute('data-original-text', button.innerHTML);
    }
    
    button.addEventListener("click", function (e) {
      e.preventDefault();
      
      // Skip if button is already processing
      if (this.disabled) return;
      
      const itemId = this.dataset.itemId;
      addItemToWishlist(itemId, this);
    });
  });
}

// Function to add an item to the cart with visual feedback
function addItemToCart(itemId, buttonElement) {
  // Store original text (might be emoji on mobile)
  const originalText = buttonElement.innerHTML;
  
  // Show loading state on button
  buttonElement.innerHTML = '<i class="fa fa-spinner fa-spin"></i>';
  buttonElement.disabled = true;
  
  fetch(`/cart/add/${itemId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" }
  })
  .then(response => {
    if (!response.ok) {
      if (response.status === 401) {
        throw new Error('Please login to add items to your cart');
      }
      throw new Error('Network response was not ok');
    }
    return response.json();
  })
  .then(data => {
    if (data.success) {
      // Update the UI
      if (document.getElementById("cart-badge")) {
        document.getElementById("cart-badge").textContent = data.cart_count;
      }
      
      // Show success feedback
      buttonElement.innerHTML = '<i class="fa fa-check"></i>';
      
      // Show notification
      showNotification("Item added to cart!", "success");
      
      // Refresh cart content
      refreshCartContent();
    } else {
      throw new Error(data.error || "Failed to add item to cart");
    }
  })
  .catch(error => {
    console.error("Error adding to cart:", error);
    buttonElement.innerHTML = '<i class="fa fa-times"></i>';
    
    // Check if login required
    if (error.message.includes('login')) {
      showNotification("Please login to add items to your cart", "warning");
    } else {
      showNotification("Error adding item to cart", "danger");
    }
  })
  .finally(() => {
    // Always reset button after a delay
    setTimeout(() => {
      buttonElement.innerHTML = originalText;
      buttonElement.disabled = false;
    }, 1500);
  });
}

// Function to add an item to the wishlist
function addItemToWishlist(itemId, buttonElement) {
  // Store original text (might be emoji on mobile)
  const originalText = buttonElement.innerHTML;
  
  buttonElement.innerHTML = '<i class="fa fa-spinner fa-spin"></i>';
  buttonElement.disabled = true;
  
  fetch(`/wishlist/add/${itemId}`, { 
    method: "POST",
    headers: { "Content-Type": "application/json" }
  })
  .then(response => {
    if (!response.ok) {
      if (response.status === 401) {
        return response.json().then(data => {
          throw new Error(data.error || 'Please login to add items to your wishlist');
        });
      }
      throw new Error('Network response was not ok');
    }
    return response.json();
  })
  .then(data => {
    if (data.success) {
      buttonElement.innerHTML = '<i class="fa fa-check"></i>';
      
      // Update badge count
      if (document.getElementById("wishlist-badge")) {
        document.getElementById("wishlist-badge").textContent = data.wishlist_count;
      }
      
      showNotification("Item added to wishlist!", "success");
    } else {
      throw new Error(data.error || "Failed to add to wishlist");
    }
  })
  .catch(error => {
    console.error("Error adding to wishlist:", error);
    buttonElement.innerHTML = '<i class="fa fa-times"></i>';
    
    // Check if login required
    if (error.message.includes('login')) {
      showNotification("Please login to add items to your wishlist", "warning");
    } else {
      showNotification("Error adding item to wishlist", "danger");
    }
  })
  .finally(() => {
    // Always reset button after a delay
    setTimeout(() => {
      buttonElement.innerHTML = originalText;
      buttonElement.disabled = false;
    }, 1500);
  });
}

// Function to refresh cart content
function refreshCartContent() {
  fetch('/cart')
    .then(response => response.text())
    .then(html => {
      const parser = new DOMParser();
      const doc = parser.parseFromString(html, 'text/html');
      
      // Extract cart items
      const newCartContent = doc.querySelector('.cart-content');
      if (newCartContent) {
        document.querySelector('.cart-content').innerHTML = newCartContent.innerHTML;
      }
      
      // Extract cart total
      const newTotalPrice = doc.querySelector('.total-price');
      if (newTotalPrice) {
        document.querySelector('.total-price').textContent = newTotalPrice.textContent;
      }
      
      // Re-attach event listeners to the new cart items
      document.querySelectorAll(".update-quantity").forEach((button) => {
        button.addEventListener("click", function() {
          const cartItemId = this.dataset.cartItemId;
          const action = this.dataset.action;
          
          fetch(`/cart/update/${cartItemId}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action }),
          })
            .then(response => response.json())
            .then(data => {
              // Update UI with the new data
              const cartBox = this.closest(".cart-box");
              cartBox.querySelector(".quantity").textContent = data.quantity;
              cartBox.querySelector(".carttotal" + cartItemId).textContent = `$${parseFloat(data.total_price).toFixed(2)}`;
              updateCartTotal(data.cart_total);
            })
            .catch(error => console.error("Error updating quantity:", error));
        });
      });
      
      document.querySelectorAll(".remove-from-cart").forEach((button) => {
        button.addEventListener("click", function() {
          const cartItemId = this.dataset.cartItemId;
          removeCartItem(cartItemId);
        });
      });
    })
    .catch(error => console.error("Error refreshing cart:", error));
}

// Show notification
function showNotification(message, type) {
  const notification = document.createElement('div');
  notification.className = `alert alert-${type} alert-dismissible fade show notification-toast`;
  notification.innerHTML = `
    ${message}
    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
  `;
  
  notification.style.position = 'fixed';
  notification.style.top = '20px';
  notification.style.right = '20px';
  notification.style.zIndex = '1050';
  notification.style.minWidth = '250px';
  
  document.body.appendChild(notification);
  
  // Auto dismiss after 3 seconds
  setTimeout(() => {
    notification.classList.remove('show');
    setTimeout(() => {
      notification.remove();
    }, 500);
  }, 3000);
}

// Function to update all counters
function updateCounters() {
  fetch("/api/counters")
    .then((response) => response.json())
    .then((data) => {
      if (document.getElementById("cart-badge")) {
        document.getElementById("cart-badge").textContent = data.cart_count;
      }
      if (document.getElementById("wishlist-badge")) {
        document.getElementById("wishlist-badge").textContent = data.wishlist_count;
      }
      if (document.getElementById("orders-badge")) {
        document.getElementById("orders-badge").textContent = data.orders_count;
      }
      if (document.getElementById("messages-badge")) {
        document.getElementById("messages-badge").textContent = data.unread_messages_count;
      }
      
      // Update cart if it's open
      const cart = document.querySelector(".cart");
      if (cart && cart.classList.contains("active")) {
        refreshCartContent();
      }
    })
    .catch((error) => console.error("Error updating counters:", error));
}

// Mobile touch support for product cards
function setupMobileTouchSupport() {
  // Detect if we're on a mobile device
  const isMobile = window.matchMedia("(max-width: 576px)").matches;
  
  if (isMobile) {
    const cards = document.querySelectorAll('.sing-card');
    
    cards.forEach(card => {
      // First tap shows overlay, second tap follows link
      let tapped = false;
      
      card.addEventListener('click', function(e) {
        // If an action button was clicked, let the event propagate
        if (e.target.closest('.add-to-cart') || 
            e.target.closest('.add-to-wishlist') || 
            e.target.closest('.btnn')) {
          return;
        }
        
        // If this is the first tap
        if (!tapped) {
          e.preventDefault();
          
          // Remove active state from all other cards
          cards.forEach(c => {
            if (c !== card) c.classList.remove('active-mobile');
          });
          
          // Toggle active state on this card
          card.classList.toggle('active-mobile');
          tapped = card.classList.contains('active-mobile');
        } else {
          // Second tap, allow normal behavior
          tapped = false;
        }
      });
    });
    
    // Replace button text with icons for mobile
    document.querySelectorAll('.add-to-cart').forEach(button => {
      button.setAttribute('data-original-text', button.innerHTML);
      button.innerHTML = '🛒';
      button.classList.add('mobile-cart-icon');
    });
    
    document.querySelectorAll('.add-to-wishlist').forEach(button => {
      button.setAttribute('data-original-text', button.innerHTML);
      button.innerHTML = '⭐';
      button.classList.add('mobile-wishlist-icon');
    });
    
    document.querySelectorAll('.btnn').forEach(link => {
      link.setAttribute('data-original-text', link.innerHTML);
      link.innerHTML = '👁️';
      link.classList.add('mobile-view-icon');
    });
  }
}