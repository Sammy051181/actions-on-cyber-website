
document.addEventListener('DOMContentLoaded', function(){
  const toggle = document.querySelector('.mobile-toggle');
  const nav = document.querySelector('.nav');
  if(toggle && nav){
    toggle.addEventListener('click', function(){
      nav.classList.toggle('open');
      toggle.setAttribute('aria-expanded', nav.classList.contains('open') ? 'true' : 'false');
    });
  }

  document.querySelectorAll('[data-mailto-form]').forEach(function(form){
    form.addEventListener('submit', function(e){
      e.preventDefault();
      const data = new FormData(form);
      const name = encodeURIComponent(data.get('name') || '');
      const email = encodeURIComponent(data.get('email') || '');
      const org = encodeURIComponent(data.get('organisation') || '');
      const topic = encodeURIComponent(data.get('topic') || '');
      const msg = encodeURIComponent(data.get('message') || '');
      const subject = encodeURIComponent('Actions On Cyber enquiry');
      const body = `Name: ${name}%0AEmail: ${email}%0AOrganisation: ${org}%0ATopic: ${topic}%0A%0AMessage:%0A${msg}`;
      window.location.href = `mailto:hello@actionsoncyber.com?subject=${subject}&body=${body}`;
    });
  });
});
