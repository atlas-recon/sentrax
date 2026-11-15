export const CONTACT_EMAIL = "coresecsecurity@gmail.com";
export const CONTACT_PHONE = "+255 773 841 274";
export const CONTACT_PHONE_DIAL = "+255773841274";
export const WHATSAPP_NUMBER = "255773841274";

export function whatsappLink(message: string): string {
  return `https://wa.me/${WHATSAPP_NUMBER}?text=${encodeURIComponent(message)}`;
}
