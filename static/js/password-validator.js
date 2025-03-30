function validatePassword(passwordField, strengthMeterElement, feedbackElement) {
    const password = passwordField.value;
    
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasSymbol = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
    const hasMinLength = password.length >= minLength;
    
    let strength = 0;
    let feedbackText = '';
    
    if (hasMinLength) {
      strength += 34;
      feedbackText += '<span class="text-success">✓ At least 8 characters</span><br>';
    } else {
      feedbackText += '<span class="text-danger">✗ At least 8 characters</span><br>';
    }
    
    if (hasUpperCase) {
      strength += 33;
      feedbackText += '<span class="text-success">✓ At least one uppercase letter</span><br>';
    } else {
      feedbackText += '<span class="text-danger">✗ At least one uppercase letter</span><br>';
    }
    
    if (hasSymbol) {
      strength += 33;
      feedbackText += '<span class="text-success">✓ At least one symbol</span><br>';
    } else {
      feedbackText += '<span class="text-danger">✗ At least one symbol</span><br>';
    }
    
    strengthMeterElement.style.width = strength + '%';
    
    if (strength < 34) {
      strengthMeterElement.className = 'progress-bar bg-danger';
    } else if (strength < 67) {
      strengthMeterElement.className = 'progress-bar bg-warning';
    } else if (strength < 100) {
      strengthMeterElement.className = 'progress-bar bg-info';
    } else {
      strengthMeterElement.className = 'progress-bar bg-success';
    }
    
    feedbackElement.innerHTML = feedbackText;
    
    return hasMinLength && hasUpperCase && hasSymbol;
  }
  
  function initPasswordValidation(passwordFieldId, confirmFieldId, strengthMeterId, feedbackId, formId) {
    const passwordField = document.getElementById(passwordFieldId);
    const confirmField = document.getElementById(confirmFieldId);
    const strengthMeter = document.getElementById(strengthMeterId);
    const feedbackElement = document.getElementById(feedbackId);
    const form = document.getElementById(formId);
    
    if (!passwordField || !strengthMeter || !feedbackElement) {
      console.error('Password validation elements not found');
      return;
    }
    
    passwordField.addEventListener('input', function() {
      const isValid = validatePassword(passwordField, strengthMeter, feedbackElement);
      
      if (passwordField.value) {
        feedbackElement.style.display = 'block';
      } else {
        feedbackElement.style.display = 'none';
      }
      
      if (confirmField && confirmField.value) {
        validatePasswordMatch(passwordField, confirmField);
      }
    });
    
    if (confirmField) {
      confirmField.addEventListener('input', function() {
        validatePasswordMatch(passwordField, confirmField);
      });
    }
    
    if (form) {
      form.addEventListener('submit', function(e) {
        const isValid = validatePassword(passwordField, strengthMeter, feedbackElement);
        
        let matchValid = true;
        if (confirmField) {
          matchValid = validatePasswordMatch(passwordField, confirmField);
        }
        
        if (!isValid || !matchValid) {
          e.preventDefault();
          alert('Please ensure your password meets all requirements.');
        }
      });
    }
  }
  
  function validatePasswordMatch(passwordField, confirmField) {
    const passwordMatch = passwordField.value === confirmField.value;
    
    if (confirmField.value) {
      if (passwordMatch) {
        confirmField.classList.remove('is-invalid');
        confirmField.classList.add('is-valid');
        return true;
      } else {
        confirmField.classList.remove('is-valid');
        confirmField.classList.add('is-invalid');
        return false;
      }
    }
    
    return true;
  }